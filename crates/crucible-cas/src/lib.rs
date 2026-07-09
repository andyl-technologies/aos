//! Content-addressed storage primitives for Crucible.
//!
//! `crucible-cas` owns the small standalone substrate required by RFC-0010:
//! BLAKE3 content keys, a minimal `put`/`get`/`has` store interface, local and
//! in-memory implementations, a fleet-visible shared implementation, and a
//! dependency-gated invalidation query. The crate intentionally has
//! no dependency on RFC-0007 `ratchet` crates; any future shared substrate must
//! adapt behind this crate's public interface and pass `gate:content-address`
//! and `gate:replay-oracle` unchanged.
//!
//! Spec index: RFC-0010 files 35.
//!
//! Future RFC-0007 integration marker: RFC-0007 is the future home for a shared
//! content-addressed store plus dependency-gated invalidation substrate. The
//! narrow interface is exactly [`DagStore::put`], [`DagStore::get`],
//! [`DagStore::has`], and [`InvalidationQuery::evaluate`]. [`SharedDagStore`] is
//! the fleet-visible backend for that same seam; dependency-gated invalidation is
//! not a second substrate.
//! Merge invariant: thin adapter behind that unchanged interface.
//! No Crucible ABI or determinism contract may change, and the adapter replaces
//! these internals only after `gate:content-address`, `gate:replay-oracle`, and
//! `gate:e2e-determinism` pass unchanged. Until then, no RFC-0007 dependency
//! exists.
//! Standalone rule: no RFC-0007 dependency exists.
//!
//! Module map: the crate root owns [`ContentHash`], [`DagStore`],
//! [`MemoryDagStore`], [`LocalDagStore`], [`SharedDagStore`],
//! [`SharedFrontier`], [`FrontierClaimRequest`], [`FrontierLease`],
//! [`SoftHashAffinity`], [`SharedDedupIndex`], [`ExpansionDedupDecision`],
//! [`CoverageAdmission`], [`ReductionAdmission`], [`SharedCampaignStore`],
//! [`CampaignReplayArtifact`], [`CampaignCorpusSeed`], [`CampaignCoverageDelta`],
//! [`CampaignFinding`], [`CampaignCorpusRetentionPolicy`], [`CampaignGcRoots`],
//! [`CampaignFreshLineageRoots`], [`CampaignManifest`],
//! [`CampaignProvenance`], [`CampaignContinuitySeedDecision`], and the
//! invalidation types [`DependencySnapshot`], [`InvalidationQuery`], and
//! [`InvalidationDecision`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use rustix::fs::{FlockOperation, flock};
use thiserror::Error;

/// Marks the future RFC-0007 merge seam for the standalone CAS substrate.
///
/// The value names the stable boundary a future shared substrate must adapt
/// behind; it is a documentation and conformance marker, not a dependency.
pub const FUTURE_RATCHET_INTEGRATION_SEAM: &str = "crucible-cas::dag-store";

/// Lists the gates a future shared substrate must pass without behavior change.
pub const FUTURE_RATCHET_MERGE_BAR: &str =
    "gate:content-address,gate:replay-oracle,gate:e2e-determinism";

/// States the ABI and determinism stability rule for a future shared substrate.
pub const FUTURE_RATCHET_STABILITY_RULE: &str =
    "no Crucible ABI or determinism contract may change";

/// Names the fleet-store and invalidation members of the same future seam.
pub const FUTURE_RATCHET_SHARED_SEAM: &str = "SharedDagStore+InvalidationQuery::evaluate";

/// Lists the exact public surface a future ratchet adapter must preserve.
pub const FUTURE_RATCHET_SEAM_INTERFACE: &str =
    "DagStore::put,DagStore::get,DagStore::has,SharedDagStore,InvalidationQuery::evaluate";

/// Schema for campaign provenance keys.
pub const CAMPAIGN_PROVENANCE_SCHEMA: &str = "crucible.campaign.provenance.v1";

/// Schema for campaign lineage ids.
pub const CAMPAIGN_LINEAGE_SCHEMA: &str = "crucible.campaign.lineage.v1";

/// Schema for a fresh-lineage baseline event.
pub const CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA: &str =
    "crucible.campaign.fresh-lineage-baseline.v1";

/// Reason recorded when a prior corpus is refused across provenance boundaries.
pub const CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON: &str = "cross-provenance-corpus-reuse-refused";

/// A BLAKE3 content address for raw store bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentHash {
    /// The canonical 32-byte BLAKE3 digest.
    pub bytes: [u8; 32],
}

impl ContentHash {
    /// Computes a content hash for `bytes`.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let digest = blake3::hash(bytes);
        Self {
            bytes: *digest.as_bytes(),
        }
    }

    /// Renders the content hash as 64 lowercase hexadecimal characters.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(self.bytes.len() * 2);
        for byte in self.bytes {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }

    /// Parses a lowercase or uppercase 64-character hexadecimal content hash.
    #[must_use]
    pub fn from_hex(hex: &str) -> Option<Self> {
        if hex.len() != 64 {
            return None;
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            bytes[index] = (high << 4) | low;
        }
        Some(Self { bytes })
    }
}

/// Error returned by a content-addressed store or invalidation query.
#[derive(Debug, Error)]
pub enum CasError {
    /// No object exists at the requested key.
    #[error("content-addressed object was not found")]
    NotFound {
        /// The missing content-addressed key.
        key: ContentHash,
    },
    /// Stored bytes did not hash to the key they were read through.
    #[error("content-addressed object did not match its key")]
    ContentMismatch {
        /// The key requested by the caller.
        expected: ContentHash,
        /// The key computed from the retrieved bytes.
        actual: ContentHash,
    },
    /// A local store lock was poisoned.
    #[error("content-addressed store lock was poisoned during {operation}")]
    StorePoisoned {
        /// The operation that needed the poisoned lock.
        operation: &'static str,
    },
    /// The backend could not complete a filesystem operation.
    #[error("content-addressed store filesystem operation {operation} failed for {path}")]
    Io {
        /// The operation being performed.
        operation: &'static str,
        /// The path involved in the failed operation.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: io::Error,
    },
    /// A frontier lease request was malformed.
    #[error("frontier lease request is invalid: {reason}")]
    InvalidLease {
        /// The reason the lease request is invalid.
        reason: &'static str,
    },
    /// A shared-frontier marker or claim record was malformed.
    #[error("shared frontier record is invalid at {path}: {reason}")]
    InvalidFrontierRecord {
        /// The invalid record path.
        path: PathBuf,
        /// The reason the record is invalid.
        reason: &'static str,
    },
    /// A campaign manifest or head record was malformed.
    #[error("campaign record is invalid at {path}: {reason}")]
    InvalidCampaignRecord {
        /// The invalid record path.
        path: PathBuf,
        /// The reason the record is invalid.
        reason: &'static str,
    },
}

/// Backend-agnostic content-addressed store for temporal-graph objects.
pub trait DagStore: Send + Sync {
    /// Stores `bytes` and returns their content-addressed key.
    ///
    /// Re-inserting the same bytes returns the same key without creating a
    /// duplicate logical object.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the backend cannot persist or validate the
    /// object.
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, CasError>;

    /// Retrieves the bytes addressed by `key`.
    ///
    /// # Errors
    ///
    /// Returns [`CasError::NotFound`] when the object is absent, or another
    /// [`CasError`] when the backend cannot read or validate it.
    fn get(&self, key: &ContentHash) -> Result<Vec<u8>, CasError>;

    /// Returns whether a valid object for `key` is present.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the backend cannot query or validate the
    /// object.
    fn has(&self, key: &ContentHash) -> Result<bool, CasError>;
}

/// In-memory [`DagStore`] implementation used by model tests and adapters.
#[derive(Debug, Default)]
pub struct MemoryDagStore {
    objects: Mutex<BTreeMap<ContentHash, Vec<u8>>>,
}

impl MemoryDagStore {
    /// Builds an empty in-memory DAG store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of unique objects currently held by the store.
    ///
    /// # Errors
    ///
    /// Returns [`CasError::StorePoisoned`] if a prior panic poisoned the store
    /// lock.
    pub fn object_count(&self) -> Result<usize, CasError> {
        let objects = self.objects.lock().map_err(|_| CasError::StorePoisoned {
            operation: "object-count",
        })?;
        Ok(objects.len())
    }
}

impl DagStore for MemoryDagStore {
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, CasError> {
        let key = ContentHash::from_bytes(bytes);
        let mut objects = self
            .objects
            .lock()
            .map_err(|_| CasError::StorePoisoned { operation: "put" })?;
        match objects.entry(key) {
            Entry::Vacant(entry) => {
                entry.insert(bytes.to_vec());
            }
            Entry::Occupied(_) => {}
        }
        Ok(key)
    }

    fn get(&self, key: &ContentHash) -> Result<Vec<u8>, CasError> {
        let objects = self
            .objects
            .lock()
            .map_err(|_| CasError::StorePoisoned { operation: "get" })?;
        objects
            .get(key)
            .cloned()
            .ok_or(CasError::NotFound { key: *key })
    }

    fn has(&self, key: &ContentHash) -> Result<bool, CasError> {
        let objects = self
            .objects
            .lock()
            .map_err(|_| CasError::StorePoisoned { operation: "has" })?;
        Ok(objects.contains_key(key))
    }
}

/// Filesystem-backed [`DagStore`] using the RFC-0010 two-level layout.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LocalDagStore {
    root: PathBuf,
}

impl LocalDagStore {
    /// Builds a local DAG store rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the store root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the two-level object path for `key`.
    ///
    /// The layout is `{root}/{first 2 hex chars}/{full hex hash}`.
    #[must_use]
    pub fn object_path(&self, key: &ContentHash) -> PathBuf {
        let hex = key.to_hex();
        self.root.join(&hex[0..2]).join(hex)
    }
}

impl DagStore for LocalDagStore {
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, CasError> {
        let key = ContentHash::from_bytes(bytes);
        let path = self.object_path(&key);
        let replace_existing = match fs::read(&path) {
            Ok(existing) => {
                if ContentHash::from_bytes(&existing) == key && existing == bytes {
                    return Ok(key);
                }
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(source) => {
                return Err(CasError::Io {
                    operation: "read",
                    path,
                    source,
                });
            }
        };

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| CasError::Io {
                operation: "create-dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let temp_path = local_store_temp_path(&path, &key);
        fs::write(&temp_path, bytes).map_err(|source| CasError::Io {
            operation: "write",
            path: temp_path.clone(),
            source,
        })?;
        if replace_existing {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(source) => {
                    let _ = fs::remove_file(&temp_path);
                    return Err(CasError::Io {
                        operation: "remove",
                        path,
                        source,
                    });
                }
            }
        }
        if let Err(source) = fs::rename(&temp_path, &path) {
            let existing_matches = fs::read(&path)
                .map(|existing| ContentHash::from_bytes(&existing) == key && existing == bytes)
                .unwrap_or(false);
            if existing_matches {
                let _ = fs::remove_file(&temp_path);
                return Ok(key);
            }
            let _ = fs::remove_file(&temp_path);
            return Err(CasError::Io {
                operation: "rename",
                path,
                source,
            });
        }
        Ok(key)
    }

    fn get(&self, key: &ContentHash) -> Result<Vec<u8>, CasError> {
        let path = self.object_path(key);
        let bytes = fs::read(&path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                CasError::NotFound { key: *key }
            } else {
                CasError::Io {
                    operation: "read",
                    path: path.clone(),
                    source,
                }
            }
        })?;
        let actual = ContentHash::from_bytes(&bytes);
        if actual != *key {
            return Err(CasError::ContentMismatch {
                expected: *key,
                actual,
            });
        }
        Ok(bytes)
    }

    fn has(&self, key: &ContentHash) -> Result<bool, CasError> {
        match self.get(key) {
            Ok(_) => Ok(true),
            Err(CasError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// Fleet-visible filesystem [`DagStore`] with idempotent concurrent publish.
///
/// `SharedDagStore` uses the same two-level object layout as [`LocalDagStore`],
/// but publishes objects through a per-writer temporary path and atomic hard-link
/// creation. Concurrent writers that publish identical bytes converge on the
/// same key and object path; a writer that finds different bytes under the same
/// key fails loudly with [`CasError::ContentMismatch`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SharedDagStore {
    root: PathBuf,
}

impl SharedDagStore {
    /// Builds a shared DAG store rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the store root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the two-level object path for `key`.
    ///
    /// The layout is `{root}/{first 2 hex chars}/{full hex hash}`.
    #[must_use]
    pub fn object_path(&self, key: &ContentHash) -> PathBuf {
        let hex = key.to_hex();
        self.root.join(&hex[0..2]).join(hex)
    }
}

impl DagStore for SharedDagStore {
    fn put(&self, bytes: &[u8]) -> Result<ContentHash, CasError> {
        let key = ContentHash::from_bytes(bytes);
        let path = self.object_path(&key);
        match fs::read(&path) {
            Ok(existing) if existing == bytes && ContentHash::from_bytes(&existing) == key => {
                return Ok(key);
            }
            Ok(existing) => {
                return Err(CasError::ContentMismatch {
                    expected: key,
                    actual: ContentHash::from_bytes(&existing),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(CasError::Io {
                    operation: "read",
                    path,
                    source,
                });
            }
        }

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| CasError::Io {
                operation: "create-dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let temp_path = create_shared_store_temp_file(&path, &key, bytes)?;

        match fs::hard_link(&temp_path, &path) {
            Ok(()) => {
                let _ = fs::remove_file(&temp_path);
                Ok(key)
            }
            Err(source) => {
                let existing = fs::read(&path);
                let _ = fs::remove_file(&temp_path);
                match existing {
                    Ok(existing)
                        if existing == bytes && ContentHash::from_bytes(&existing) == key =>
                    {
                        Ok(key)
                    }
                    Ok(existing) => Err(CasError::ContentMismatch {
                        expected: key,
                        actual: ContentHash::from_bytes(&existing),
                    }),
                    Err(error) if source.kind() == io::ErrorKind::AlreadyExists => {
                        Err(CasError::Io {
                            operation: "read",
                            path,
                            source: error,
                        })
                    }
                    Err(_) => Err(CasError::Io {
                        operation: "hard-link",
                        path,
                        source,
                    }),
                }
            }
        }
    }

    fn get(&self, key: &ContentHash) -> Result<Vec<u8>, CasError> {
        let path = self.object_path(key);
        let bytes = fs::read(&path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                CasError::NotFound { key: *key }
            } else {
                CasError::Io {
                    operation: "read",
                    path: path.clone(),
                    source,
                }
            }
        })?;
        let actual = ContentHash::from_bytes(&bytes);
        if actual != *key {
            return Err(CasError::ContentMismatch {
                expected: *key,
                actual,
            });
        }
        Ok(bytes)
    }

    fn has(&self, key: &ContentHash) -> Result<bool, CasError> {
        match self.get(key) {
            Ok(_) => Ok(true),
            Err(CasError::NotFound { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// Fleet-visible content-addressed frontier with TTL claim leases.
///
/// `SharedFrontier` stores frontier membership under paths derived only from a
/// node [`ContentHash`]. Claim records live beside that frontier and contain
/// distribution metadata such as host id and lease expiry, but those values never
/// enter the frontier key. Claims are hints: an expired or missing claim makes the
/// same node claimable again, so repeated work reuses the same content address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SharedFrontier {
    root: PathBuf,
}

impl SharedFrontier {
    /// Builds a shared frontier rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the shared frontier root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the membership marker path for `node`.
    ///
    /// The path is keyed only by the frontier node content address.
    #[must_use]
    pub fn frontier_path(&self, node: &ContentHash) -> PathBuf {
        content_path(&self.root.join("frontier"), node)
    }

    /// Returns the claim record path for `node`.
    ///
    /// Host id, lease timestamps, and affinity hints never appear in this path.
    #[must_use]
    pub fn claim_path(&self, node: &ContentHash) -> PathBuf {
        content_path(&self.root.join("claims"), node)
    }

    fn claim_lock_path(&self, node: &ContentHash) -> PathBuf {
        content_path(&self.root.join("claim-locks"), node)
    }

    /// Admits `node` to the shared frontier.
    ///
    /// Re-admitting the same node is idempotent.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the marker cannot be persisted.
    pub fn admit(&self, node: &ContentHash) -> Result<(), CasError> {
        let path = self.frontier_path(node);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| CasError::Io {
                operation: "create-dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }

        let material = format!("format=crucible.frontier-node.v1\nnode={}\n", node.to_hex());
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => file
                .write_all(material.as_bytes())
                .map_err(|source| CasError::Io {
                    operation: "write",
                    path,
                    source,
                }),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(source) => Err(CasError::Io {
                operation: "create",
                path,
                source,
            }),
        }
    }

    /// Returns currently claimable frontier nodes in content-address order.
    ///
    /// A node is claimable when it has no claim record or its claim record has
    /// expired at `now_tick`.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the frontier or claim records cannot be read or
    /// parsed.
    pub fn claimable_nodes(&self, now_tick: u64) -> Result<Vec<ContentHash>, CasError> {
        let mut nodes = Vec::new();
        for node in self.frontier_nodes()? {
            if self.is_claimable(&node, now_tick)? {
                nodes.push(node);
            }
        }
        Ok(nodes)
    }

    /// Returns claimable nodes ordered with soft affinity as a priority hint.
    ///
    /// Every node returned by [`Self::claimable_nodes`] is still returned here;
    /// affinity only moves preferred nodes earlier.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the frontier or claim records cannot be read or
    /// parsed.
    pub fn ordered_claimable_nodes(
        &self,
        now_tick: u64,
        affinity: &SoftHashAffinity,
    ) -> Result<Vec<ContentHash>, CasError> {
        let mut nodes = self.claimable_nodes(now_tick)?;
        nodes.sort_by_key(|node| (!affinity.prefers(node), *node));
        Ok(nodes)
    }

    /// Claims the next available frontier node for `request`.
    ///
    /// The selected claim is recorded at a path keyed by the node content address.
    /// If all nodes are currently leased, this returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the request is invalid or the frontier/claim
    /// records cannot be read or updated.
    pub fn claim_next(
        &self,
        request: &FrontierClaimRequest,
    ) -> Result<Option<FrontierLease>, CasError> {
        validate_claim_request(request)?;
        for node in self.ordered_claimable_nodes(request.now_tick, &request.affinity)? {
            let Some(_claim_lock) =
                self.try_claim_lock(&node, request.now_tick, request.ttl_ticks)?
            else {
                continue;
            };
            if self.is_claimable(&node, request.now_tick)? {
                return self.write_lease(&node, request).map(Some);
            }
        }
        Ok(None)
    }

    /// Renews `lease` if this store still owns that lease.
    ///
    /// Returns `Ok(None)` when the lease was already released, replaced, or
    /// expired.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the lease request is invalid or the claim record
    /// cannot be read or updated.
    pub fn renew(
        &self,
        lease: &FrontierLease,
        now_tick: u64,
        ttl_ticks: u64,
    ) -> Result<Option<FrontierLease>, CasError> {
        let request = FrontierClaimRequest::new(lease.owner.clone(), now_tick, ttl_ticks);
        validate_claim_request(&request)?;
        let Some(_claim_lock) = self.try_claim_lock(&lease.node, now_tick, ttl_ticks)? else {
            return Ok(None);
        };
        let Some(current) = self.current_lease(&lease.node)? else {
            return Ok(None);
        };
        if current.lease_id != lease.lease_id || current.is_expired(now_tick) {
            return Ok(None);
        }
        self.write_lease(&lease.node, &request).map(Some)
    }

    /// Releases `lease` when this store still owns it.
    ///
    /// Returns `Ok(false)` when the lease was already released, replaced, or
    /// expired.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the claim record cannot be read or removed.
    pub fn release(&self, lease: &FrontierLease) -> Result<bool, CasError> {
        let lock_now_tick = lease.expires_at_tick.saturating_sub(1);
        let Some(_claim_lock) = self.try_claim_lock(&lease.node, lock_now_tick, 1)? else {
            return Ok(false);
        };
        let Some(current) = self.current_lease(&lease.node)? else {
            return Ok(false);
        };
        if current.lease_id != lease.lease_id {
            return Ok(false);
        }
        let path = self.claim_path(&lease.node);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(CasError::Io {
                operation: "remove",
                path,
                source,
            }),
        }
    }

    fn frontier_nodes(&self) -> Result<Vec<ContentHash>, CasError> {
        let root = self.root.join("frontier");
        if !root.exists() {
            return Ok(Vec::new());
        }
        let mut nodes = BTreeSet::new();
        for bucket in fs::read_dir(&root).map_err(|source| CasError::Io {
            operation: "read-dir",
            path: root.clone(),
            source,
        })? {
            let bucket = bucket.map_err(|source| CasError::Io {
                operation: "read-dir-entry",
                path: root.clone(),
                source,
            })?;
            let bucket_path = bucket.path();
            if !bucket
                .file_type()
                .map_err(|source| CasError::Io {
                    operation: "file-type",
                    path: bucket_path.clone(),
                    source,
                })?
                .is_dir()
            {
                continue;
            }
            for entry in fs::read_dir(&bucket_path).map_err(|source| CasError::Io {
                operation: "read-dir",
                path: bucket_path.clone(),
                source,
            })? {
                let entry = entry.map_err(|source| CasError::Io {
                    operation: "read-dir-entry",
                    path: bucket_path.clone(),
                    source,
                })?;
                let entry_path = entry.path();
                if entry
                    .file_type()
                    .map_err(|source| CasError::Io {
                        operation: "file-type",
                        path: entry_path.clone(),
                        source,
                    })?
                    .is_file()
                {
                    let name = entry.file_name();
                    let name = name
                        .to_str()
                        .ok_or_else(|| CasError::InvalidFrontierRecord {
                            path: entry_path.clone(),
                            reason: "frontier marker name is not UTF-8",
                        })?;
                    let node = ContentHash::from_hex(name).ok_or({
                        CasError::InvalidFrontierRecord {
                            path: entry_path,
                            reason: "frontier marker name is not a content hash",
                        }
                    })?;
                    nodes.insert(node);
                }
            }
        }
        Ok(nodes.into_iter().collect())
    }

    fn is_claimable(&self, node: &ContentHash, now_tick: u64) -> Result<bool, CasError> {
        match self.current_lease(node)? {
            Some(lease) => Ok(lease.is_expired(now_tick)),
            None => Ok(true),
        }
    }

    fn current_lease(&self, node: &ContentHash) -> Result<Option<FrontierLease>, CasError> {
        let path = self.claim_path(node);
        let material = match fs::read_to_string(&path) {
            Ok(material) => material,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CasError::Io {
                    operation: "read",
                    path,
                    source,
                });
            }
        };
        parse_lease_record(&path, node, &material).map(Some)
    }

    fn try_claim_lock(
        &self,
        node: &ContentHash,
        now_tick: u64,
        ttl_ticks: u64,
    ) -> Result<Option<FrontierClaimLock>, CasError> {
        let path = self.claim_lock_path(node);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| CasError::Io {
                operation: "create-dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        loop {
            match self.publish_claim_lock(&path, node, now_tick, ttl_ticks)? {
                Some(lock) => return Ok(Some(lock)),
                None => {
                    let Some(current) = self.current_claim_lock(node)? else {
                        continue;
                    };
                    if !current.is_expired(now_tick) {
                        return Ok(None);
                    }
                    match fs::remove_file(&path) {
                        Ok(()) => continue,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                        Err(source) => {
                            return Err(CasError::Io {
                                operation: "remove",
                                path,
                                source,
                            });
                        }
                    }
                }
            }
        }
    }

    fn current_claim_lock(
        &self,
        node: &ContentHash,
    ) -> Result<Option<FrontierClaimLockRecord>, CasError> {
        let path = self.claim_lock_path(node);
        let material = match fs::read_to_string(&path) {
            Ok(material) => material,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CasError::Io {
                    operation: "read",
                    path,
                    source,
                });
            }
        };
        parse_claim_lock_record(&path, node, &material).map(Some)
    }

    fn publish_claim_lock(
        &self,
        path: &Path,
        node: &ContentHash,
        now_tick: u64,
        ttl_ticks: u64,
    ) -> Result<Option<FrontierClaimLock>, CasError> {
        let expires_at_tick = now_tick
            .checked_add(ttl_ticks)
            .ok_or(CasError::InvalidLease {
                reason: "lease expiry tick overflows u64",
            })?;
        let material = claim_lock_record_material(node, now_tick, expires_at_tick);
        let (temp_path, mut temp_file) = loop {
            let temp_path = frontier_claim_lock_temp_path(path, node, expires_at_tick);
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
            {
                Ok(file) => break (temp_path, file),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(source) => {
                    return Err(CasError::Io {
                        operation: "create",
                        path: temp_path,
                        source,
                    });
                }
            }
        };
        if let Err(source) = temp_file.write_all(material.as_bytes()) {
            let _ = fs::remove_file(&temp_path);
            return Err(CasError::Io {
                operation: "write",
                path: temp_path,
                source,
            });
        }
        drop(temp_file);

        match fs::hard_link(&temp_path, path) {
            Ok(()) => {
                let _ = fs::remove_file(&temp_path);
                Ok(Some(FrontierClaimLock {
                    path: path.to_path_buf(),
                }))
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let _ = fs::remove_file(&temp_path);
                Ok(None)
            }
            Err(source) => {
                let _ = fs::remove_file(&temp_path);
                Err(CasError::Io {
                    operation: "link",
                    path: path.to_path_buf(),
                    source,
                })
            }
        }
    }

    fn write_lease(
        &self,
        node: &ContentHash,
        request: &FrontierClaimRequest,
    ) -> Result<FrontierLease, CasError> {
        let expires_at_tick =
            request
                .now_tick
                .checked_add(request.ttl_ticks)
                .ok_or(CasError::InvalidLease {
                    reason: "lease expiry tick overflows u64",
                })?;
        let lease_id = frontier_lease_id(node, &request.host_id, expires_at_tick);
        let lease = FrontierLease {
            node: *node,
            owner: request.host_id.clone(),
            expires_at_tick,
            lease_id,
        };
        let path = self.claim_path(node);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| CasError::Io {
                operation: "create-dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let temp_path = frontier_claim_temp_path(&path, &lease);
        fs::write(&temp_path, lease_record_material(&lease)).map_err(|source| CasError::Io {
            operation: "write",
            path: temp_path.clone(),
            source,
        })?;
        fs::rename(&temp_path, &path).map_err(|source| {
            let _ = fs::remove_file(&temp_path);
            CasError::Io {
                operation: "rename",
                path,
                source,
            }
        })?;
        Ok(lease)
    }
}

#[derive(Debug)]
struct FrontierClaimLock {
    path: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrontierClaimLockRecord {
    node: ContentHash,
    expires_at_tick: u64,
}

impl FrontierClaimLockRecord {
    fn is_expired(&self, now_tick: u64) -> bool {
        self.expires_at_tick <= now_tick
    }
}

impl Drop for FrontierClaimLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Claim request used by a worker to lease one frontier node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontierClaimRequest {
    /// Host or worker id recorded in the claim metadata.
    pub host_id: String,
    /// Monotone logical tick used to evaluate TTL expiry.
    pub now_tick: u64,
    /// Lease duration in logical ticks.
    pub ttl_ticks: u64,
    /// Optional cache-warmth priority hint.
    pub affinity: SoftHashAffinity,
}

impl FrontierClaimRequest {
    /// Builds a claim request with affinity disabled.
    #[must_use]
    pub fn new(host_id: impl Into<String>, now_tick: u64, ttl_ticks: u64) -> Self {
        Self {
            host_id: host_id.into(),
            now_tick,
            ttl_ticks,
            affinity: SoftHashAffinity::off(),
        }
    }

    /// Sets the soft affinity hint for this request.
    #[must_use]
    pub fn with_affinity(mut self, affinity: SoftHashAffinity) -> Self {
        self.affinity = affinity;
        self
    }
}

/// A TTL-bounded claim over one content-addressed frontier node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrontierLease {
    /// The content-addressed frontier node being leased.
    pub node: ContentHash,
    /// Host or worker id recorded as lease metadata.
    pub owner: String,
    /// Logical tick at which this lease expires.
    pub expires_at_tick: u64,
    /// Content hash of the lease record material.
    pub lease_id: ContentHash,
}

impl FrontierLease {
    /// Returns whether this lease has expired at `now_tick`.
    #[must_use]
    pub fn is_expired(&self, now_tick: u64) -> bool {
        self.expires_at_tick <= now_tick
    }
}

/// Cache-warmth priority hint for shared frontier claims.
///
/// Affinity never filters the claimable frontier. Preferred nodes are tried
/// first, and all non-preferred claimable nodes remain eligible.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SoftHashAffinity {
    preferred: BTreeSet<ContentHash>,
}

impl SoftHashAffinity {
    /// Builds an affinity hint that prefers nothing.
    #[must_use]
    pub fn off() -> Self {
        Self::default()
    }

    /// Builds an affinity hint that prefers `nodes`.
    pub fn prefer(nodes: impl IntoIterator<Item = ContentHash>) -> Self {
        Self {
            preferred: nodes.into_iter().collect(),
        }
    }

    /// Returns whether `node` is preferred by this hint.
    #[must_use]
    pub fn prefers(&self, node: &ContentHash) -> bool {
        self.preferred.contains(node)
    }

    /// Returns the number of preferred nodes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.preferred.len()
    }

    /// Returns whether this hint prefers no nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.preferred.is_empty()
    }

    /// Returns the preferred frontier nodes.
    #[must_use]
    pub fn preferred(&self) -> &BTreeSet<ContentHash> {
        &self.preferred
    }
}

/// Fleet-visible index for the four redundant-work dedup layers.
///
/// The index stores only content-addressed markers. Expansion gating is read from
/// a [`DagStore`], coverage-map admission is keyed by covered entry hash,
/// reduction representatives are keyed by shared reduction fingerprint, and
/// claim-set anti-redundancy remains owned by [`SharedFrontier`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SharedDedupIndex {
    root: PathBuf,
}

impl SharedDedupIndex {
    /// Builds a shared dedup index rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the shared dedup index root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the shared coverage-map marker path for `entry`.
    ///
    /// The path is keyed only by the covered entry's content address.
    #[must_use]
    pub fn coverage_path(&self, entry: &ContentHash) -> PathBuf {
        content_path(&self.root.join("coverage-map"), entry)
    }

    /// Returns the shared coverage-fingerprint admission path for `fingerprint`.
    ///
    /// The path is keyed only by the candidate coverage fingerprint.
    #[must_use]
    pub fn coverage_fingerprint_path(&self, fingerprint: &ContentHash) -> PathBuf {
        content_path(&self.root.join("coverage-fingerprints"), fingerprint)
    }

    /// Returns the shared reduction-fingerprint marker path for `fingerprint`.
    ///
    /// The path is keyed only by the reduction fingerprint content address.
    #[must_use]
    pub fn reduction_path(&self, fingerprint: &ContentHash) -> PathBuf {
        content_path(&self.root.join("reduction-fingerprints"), fingerprint)
    }

    /// Decides whether `node` should be expanded by checking the shared store.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the store cannot answer the membership query.
    pub fn exists_gated_expansion(
        &self,
        store: &impl DagStore,
        node: &ContentHash,
    ) -> Result<ExpansionDedupDecision, CasError> {
        if store.has(node)? {
            Ok(ExpansionDedupDecision::SkipExisting)
        } else {
            Ok(ExpansionDedupDecision::Expand)
        }
    }

    /// Admits coverage entries when at least one entry is new to the shared map.
    ///
    /// Duplicate entries are skipped. The returned admission is novel when one or
    /// more content-addressed coverage markers were created.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when a coverage marker cannot be persisted.
    pub fn admit_coverage_map<I>(
        &self,
        coverage_fingerprint: ContentHash,
        entries: I,
    ) -> Result<CoverageAdmission, CasError>
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let mut entries = entries.into_iter().collect::<Vec<_>>();
        entries.sort();
        entries.dedup();
        let fingerprint_was_committed = self
            .coverage_fingerprint_path(&coverage_fingerprint)
            .exists();

        let mut new_entries = Vec::new();
        let mut duplicate_entries = Vec::new();
        for entry in &entries {
            let path = self.coverage_path(entry);
            let material = coverage_record_material(&coverage_fingerprint, entry);
            if create_content_record(&path, &material)? {
                new_entries.push(*entry);
            } else {
                duplicate_entries.push(*entry);
            }
        }
        let fingerprint_path = self.coverage_fingerprint_path(&coverage_fingerprint);
        let _ = create_content_record(
            &fingerprint_path,
            &coverage_fingerprint_record_material(&coverage_fingerprint, &entries),
        )?;
        if fingerprint_was_committed {
            duplicate_entries = entries;
            new_entries.clear();
        }

        Ok(CoverageAdmission {
            coverage_fingerprint,
            new_entries,
            duplicate_entries,
        })
    }

    /// Admits the first representative for a shared reduction fingerprint.
    ///
    /// Later calls for the same fingerprint return the existing representative as
    /// the fleet-wide cover for the supplied candidate.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the reduction marker cannot be read, parsed, or
    /// persisted.
    pub fn admit_reduction_fingerprint(
        &self,
        fingerprint: ContentHash,
        representative: ContentHash,
    ) -> Result<ReductionAdmission, CasError> {
        let path = self.reduction_path(&fingerprint);
        let material = reduction_record_material(&fingerprint, &representative);
        if create_content_record(&path, &material)? {
            return Ok(ReductionAdmission {
                fingerprint,
                representative,
                covered: None,
            });
        }

        let existing = parse_reduction_record(
            &path,
            &fingerprint,
            &fs::read_to_string(&path).map_err(|source| CasError::Io {
                operation: "read",
                path: path.clone(),
                source,
            })?,
        )?;
        Ok(ReductionAdmission {
            fingerprint,
            representative: existing,
            covered: Some(representative),
        })
    }
}

/// Decision returned by an exists-gated expansion check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExpansionDedupDecision {
    /// The node is absent from the shared store and may be expanded.
    Expand,
    /// The node already exists in the shared store and should be skipped.
    SkipExisting,
}

impl ExpansionDedupDecision {
    /// Returns whether the node should be expanded.
    #[must_use]
    pub fn should_expand(self) -> bool {
        matches!(self, Self::Expand)
    }

    /// Returns whether the node was skipped because it already exists.
    #[must_use]
    pub fn skipped_existing(self) -> bool {
        matches!(self, Self::SkipExisting)
    }
}

/// Result of shared coverage-map compare-and-merge admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageAdmission {
    /// Coverage fingerprint associated with the candidate being admitted.
    pub coverage_fingerprint: ContentHash,
    /// Coverage entries newly added to the shared map.
    pub new_entries: Vec<ContentHash>,
    /// Coverage entries already present in the shared map.
    pub duplicate_entries: Vec<ContentHash>,
}

impl CoverageAdmission {
    /// Returns whether this candidate added any new shared coverage.
    #[must_use]
    pub fn admitted(&self) -> bool {
        !self.new_entries.is_empty()
    }

    /// Returns whether this candidate was redundant against the shared map.
    #[must_use]
    pub fn redundant(&self) -> bool {
        self.new_entries.is_empty()
    }
}

/// Result of shared symmetry or partial-order reduction-fingerprint admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReductionAdmission {
    /// Shared reduction fingerprint used for fleet-wide pruning.
    pub fingerprint: ContentHash,
    /// Representative retained for this fingerprint.
    pub representative: ContentHash,
    /// Candidate covered by the representative, if this was redundant.
    pub covered: Option<ContentHash>,
}

impl ReductionAdmission {
    /// Returns whether this candidate became the shared representative.
    #[must_use]
    pub fn admitted(&self) -> bool {
        self.covered.is_none()
    }

    /// Returns whether this candidate was covered by an existing representative.
    #[must_use]
    pub fn covered(&self) -> bool {
        self.covered.is_some()
    }
}

/// Persistent campaign store with a content-addressed manifest and CAS head.
///
/// Campaign manifests are immutable objects in the same [`SharedDagStore`] used
/// by the fleet. The only durable non-content-addressed path owned by this type is
/// [`Self::head_path`], a tiny mutable ref containing the current manifest hash.
/// Concurrent writers serialize through an advisory lock on that same file.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SharedCampaignStore {
    root: PathBuf,
    store: SharedDagStore,
}

impl SharedCampaignStore {
    /// Builds a persistent campaign store rooted at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let store = SharedDagStore::new(root.join("objects"));
        Self { root, store }
    }

    /// Returns the campaign store root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the content-addressed manifest object store.
    #[must_use]
    pub fn manifest_store(&self) -> &SharedDagStore {
        &self.store
    }

    /// Returns the single mutable campaign head path.
    #[must_use]
    pub fn head_path(&self) -> PathBuf {
        self.root.join("campaign-head")
    }

    /// Persists `manifest` as an immutable content-addressed object.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the manifest is invalid or cannot be stored.
    pub fn persist_manifest(&self, manifest: &CampaignManifest) -> Result<ContentHash, CasError> {
        validate_campaign_manifest(manifest)?;
        self.validate_manifest_roots(manifest)?;
        self.store
            .put(manifest_record_material(manifest).as_bytes())
    }

    /// Reads the current campaign head, if one exists.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the head or named manifest cannot be read or
    /// parsed.
    pub fn read_head(&self) -> Result<Option<CampaignHead>, CasError> {
        let _guard = self.acquire_head_lock(FlockOperation::LockShared)?;
        self.read_head_unlocked()
    }

    fn read_head_unlocked(&self) -> Result<Option<CampaignHead>, CasError> {
        let Some(manifest_hash) = self.read_head_hash()? else {
            return Ok(None);
        };
        let manifest = self.read_manifest_object(manifest_hash)?;
        Ok(Some(CampaignHead {
            manifest_hash,
            manifest,
        }))
    }

    /// Compares the current head to `expected` and swaps it to `manifest`.
    ///
    /// The proposed manifest is persisted before the compare step. If the compare
    /// fails, the proposed manifest remains content-addressed and recoverable, so
    /// the lost CAS loses only manifest-head bookkeeping.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the current or proposed manifest cannot be read,
    /// parsed, stored, or written to the head.
    pub fn compare_and_swap_head(
        &self,
        expected: Option<ContentHash>,
        manifest: &CampaignManifest,
    ) -> Result<CampaignCasOutcome, CasError> {
        self.compare_and_swap_head_with_storage_policy(expected, manifest, None)
    }

    /// Compares and swaps the campaign head through an explicit retention policy.
    ///
    /// This is the storage-bounding form of [`Self::compare_and_swap_head`].
    /// Ordinary head advancement remains grow-only for corpus roots; bounded
    /// corpus pruning is accepted only when the proposed retained root proves the
    /// supplied nonzero policy against the current head's corpus root.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the current or proposed manifest cannot be read,
    /// parsed, stored, or written to the head, or when the proposed retained
    /// corpus root does not match `policy`.
    pub fn compare_and_swap_head_with_retention(
        &self,
        expected: Option<ContentHash>,
        manifest: &CampaignManifest,
        policy: CampaignCorpusRetentionPolicy,
    ) -> Result<CampaignCasOutcome, CasError> {
        validate_campaign_corpus_retention_policy(&policy, self.head_path())?;
        self.compare_and_swap_head_with_storage_policy(expected, manifest, Some(policy))
    }

    fn compare_and_swap_head_with_storage_policy(
        &self,
        expected: Option<ContentHash>,
        manifest: &CampaignManifest,
        retention_policy: Option<CampaignCorpusRetentionPolicy>,
    ) -> Result<CampaignCasOutcome, CasError> {
        let proposed_manifest_hash = self.persist_manifest(manifest)?;
        let mut guard = self.acquire_head_lock(FlockOperation::LockExclusive)?;
        let current_pointer = self.read_head_pointer()?;
        let current = current_pointer.map(|pointer| pointer.manifest_hash);
        if current != expected {
            return Ok(CampaignCasOutcome::LostUpdate {
                expected,
                current,
                proposed_manifest_hash,
            });
        }
        if let Some(current_manifest_hash) = current {
            let current_manifest = self.read_manifest_object(current_manifest_hash)?;
            self.validate_monotone_manifest_advance(
                &current_manifest,
                manifest,
                retention_policy.as_ref(),
            )?;
        }
        self.write_head(&mut guard, current_pointer, proposed_manifest_hash)?;
        let head = self
            .read_head_unlocked()?
            .ok_or_else(|| CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "campaign head disappeared after CAS",
            })?;
        Ok(CampaignCasOutcome::Advanced(head))
    }

    /// Advances the campaign head with read-merge-retry semantics.
    ///
    /// On CAS conflict, this reads the winning head, merges the proposed roots
    /// into it, and retries. Provenance and genesis pins must match; changed
    /// provenance is handled by the campaign-continuity fresh-lineage fork path.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the head cannot be read or advanced, when
    /// compatible roots cannot be merged, or when `max_attempts` is exhausted.
    pub fn advance_head_with_merge(
        &self,
        proposed: &CampaignManifest,
        max_attempts: usize,
    ) -> Result<CampaignAdvanceReport, CasError> {
        if max_attempts == 0 {
            return Err(CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "campaign head merge retry requires at least one attempt",
            });
        }
        let mut attempts = 0;
        loop {
            attempts += 1;
            let current = self.read_head()?;
            let expected = current.as_ref().map(|head| head.manifest_hash);
            let next = match current {
                Some(head) => self.merge_manifests(&head.manifest, proposed)?,
                None => proposed.clone(),
            };
            match self.compare_and_swap_head(expected, &next)? {
                CampaignCasOutcome::Advanced(head) => {
                    return Ok(CampaignAdvanceReport { attempts, head });
                }
                CampaignCasOutcome::LostUpdate { .. } if attempts < max_attempts => continue,
                CampaignCasOutcome::LostUpdate { .. } => {
                    return Err(CasError::InvalidCampaignRecord {
                        path: self.head_path(),
                        reason: "campaign head CAS retry budget exhausted",
                    });
                }
            }
        }
    }

    /// Persists a self-contained replay artifact as an immutable object.
    ///
    /// The stored artifact contains the definition, seed, and schedule bytes
    /// needed to reproduce the entry without resuming a producing run.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the artifact cannot be stored.
    pub fn persist_replay_artifact(
        &self,
        artifact: &CampaignReplayArtifact,
    ) -> Result<ContentHash, CasError> {
        self.store
            .put(campaign_replay_artifact_material(artifact).as_bytes())
    }

    /// Reads and validates a self-contained replay artifact.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the artifact is missing, corrupt, or has an
    /// invalid replay hash.
    pub fn read_replay_artifact(
        &self,
        artifact_hash: ContentHash,
    ) -> Result<CampaignReplayArtifact, CasError> {
        let material = self.read_campaign_object_text(artifact_hash)?;
        parse_replay_artifact_record(&self.store.object_path(&artifact_hash), &material)
    }

    /// Persists a retained campaign corpus root.
    ///
    /// Each supplied artifact is stored first, then the corpus root records the
    /// artifact hash and replay hash. Duplicate artifacts collapse to one corpus
    /// entry by content address.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when an artifact or corpus root cannot be stored.
    pub fn persist_campaign_corpus<I>(&self, artifacts: I) -> Result<ContentHash, CasError>
    where
        I: IntoIterator<Item = CampaignReplayArtifact>,
    {
        let mut entries = BTreeMap::new();
        for artifact in artifacts {
            let artifact_hash = self.persist_replay_artifact(&artifact)?;
            entries.insert(artifact_hash, artifact.replay_hash());
        }
        self.persist_campaign_corpus_entries(&entries)
    }

    /// Loads the corpus named by `manifest` as the seed plan for run N+1.
    ///
    /// The caller must provide the provenance for the run being seeded. This API
    /// refuses drift; use [`SharedCampaignStore::seed_next_run_for_provenance`]
    /// when a changed provenance should fork a fresh campaign lineage.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the corpus root or any replay artifact is
    /// missing, corrupt, not self-validating, or keyed to different provenance
    /// than `run_provenance`.
    pub fn seed_next_run(
        &self,
        manifest: &CampaignManifest,
        run_provenance: &CampaignProvenance,
    ) -> Result<Vec<CampaignCorpusSeed>, CasError> {
        validate_campaign_manifest(manifest)?;
        validate_campaign_provenance(run_provenance)?;
        if manifest.provenance != *run_provenance {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&manifest.corpus_root),
                reason: "campaign seed provenance does not match manifest provenance",
            });
        }
        self.seed_next_run_from_prior_corpus(manifest.corpus_root)
    }

    /// Decides whether `manifest` may seed a run with `run_provenance`.
    ///
    /// Matching provenance loads the prior corpus as self-contained seed
    /// artifacts. Mismatched provenance refuses reuse, persists a fresh lineage
    /// manifest from `fresh_lineage_roots`, and returns a baseline event for the
    /// new lineage.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when campaign roots are malformed, a same-provenance
    /// seed artifact cannot reproduce its recorded replay hash, or a
    /// cross-provenance fresh lineage would reuse prior campaign roots or entries.
    pub fn seed_next_run_for_provenance(
        &self,
        manifest: &CampaignManifest,
        run_provenance: &CampaignProvenance,
        fresh_lineage_roots: CampaignFreshLineageRoots,
    ) -> Result<CampaignContinuitySeedDecision, CasError> {
        validate_campaign_manifest(manifest)?;
        validate_campaign_provenance(run_provenance)?;
        if manifest.provenance == *run_provenance {
            return Ok(CampaignContinuitySeedDecision::SeedPriorCorpus {
                seeds: self.seed_next_run(manifest, run_provenance)?,
                lineage_id: campaign_lineage_id(manifest)?,
                provenance_key: campaign_provenance_key(run_provenance)?,
            });
        }

        self.fork_fresh_campaign_lineage(manifest, run_provenance.clone(), fresh_lineage_roots)
            .map(|event| {
                CampaignContinuitySeedDecision::RefuseCrossProvenanceReuse(Box::new(event))
            })
    }

    fn seed_next_run_from_prior_corpus(
        &self,
        corpus_root: ContentHash,
    ) -> Result<Vec<CampaignCorpusSeed>, CasError> {
        self.corpus_seed_map(corpus_root)
            .map(|entries| entries.into_values().collect())
    }

    /// Persists a fresh campaign lineage after provenance drift.
    ///
    /// The fresh lineage uses new corpus, coverage, findings, and genesis roots
    /// and records `run_provenance`; the fresh manifest is installed as the
    /// campaign head when `prior` is the current head. The prior lineage remains
    /// untouched and reproducible through its original manifest.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when provenance did not change, any fresh root is
    /// malformed or missing, the prior manifest is not the current head, or the
    /// fresh roots silently reuse prior campaign corpus, coverage, or findings
    /// entries.
    pub fn fork_fresh_campaign_lineage(
        &self,
        prior: &CampaignManifest,
        run_provenance: CampaignProvenance,
        fresh_roots: CampaignFreshLineageRoots,
    ) -> Result<CampaignFreshLineageBaselineEvent, CasError> {
        validate_campaign_manifest(prior)?;
        validate_campaign_provenance(&run_provenance)?;
        if prior.provenance == run_provenance {
            return Err(CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "fresh campaign lineage requires changed provenance",
            });
        }
        self.validate_fresh_lineage_roots(prior, &fresh_roots)?;
        self.require_fresh_lineage_current_head(prior)?;

        let fresh_manifest = CampaignManifest::new(
            fresh_roots.corpus_root,
            fresh_roots.coverage_map_root,
            fresh_roots.findings_root,
            fresh_roots.genesis_pin,
            run_provenance,
        );
        let fresh_manifest_hash = self.persist_manifest(&fresh_manifest)?;
        let mut event = CampaignFreshLineageBaselineEvent {
            baseline_event_hash: ContentHash::default(),
            schema_version: CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA.to_owned(),
            reason: CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON.to_owned(),
            refused_corpus_root: prior.corpus_root,
            previous_lineage_id: campaign_lineage_id(prior)?,
            fresh_lineage_id: campaign_lineage_id(&fresh_manifest)?,
            previous_provenance_key: campaign_provenance_key(&prior.provenance)?,
            run_provenance_key: campaign_provenance_key(&fresh_manifest.provenance)?,
            fresh_manifest_hash,
            fresh_manifest,
        };
        event.baseline_event_hash = self
            .store
            .put(campaign_fresh_lineage_baseline_event_material(&event).as_bytes())?;
        self.install_fresh_lineage_head(prior, event.fresh_manifest_hash)?;
        Ok(event)
    }

    /// Reads a persisted fresh-lineage baseline event.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when `event_hash` is missing, malformed, or does not
    /// describe a valid fresh-lineage baseline event.
    pub fn read_fresh_lineage_baseline_event(
        &self,
        event_hash: ContentHash,
    ) -> Result<CampaignFreshLineageBaselineEvent, CasError> {
        let material = self.read_campaign_object_text(event_hash)?;
        let event = parse_fresh_lineage_baseline_event(
            &self.store.object_path(&event_hash),
            event_hash,
            &material,
        )?;
        let fresh_manifest = self.read_manifest_object(event.fresh_manifest_hash)?;
        if fresh_manifest != event.fresh_manifest {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&event.fresh_manifest_hash),
                reason: "fresh-lineage baseline event manifest hash does not match manifest",
            });
        }
        Ok(event)
    }

    /// Persists an accumulated coverage map root.
    ///
    /// Coverage maps are grow-only sets. Duplicate edges collapse by content
    /// address before the root object is written.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the coverage root cannot be stored.
    pub fn persist_accumulated_coverage_map<I>(&self, edges: I) -> Result<ContentHash, CasError>
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let edges = edges.into_iter().collect::<BTreeSet<_>>();
        self.persist_coverage_edges(&edges)
    }

    /// Returns the sorted coverage edges named by an accumulated coverage root.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the coverage root is missing or corrupt.
    pub fn accumulated_coverage_edges(
        &self,
        coverage_map_root: ContentHash,
    ) -> Result<Vec<ContentHash>, CasError> {
        Ok(self
            .coverage_edge_set(coverage_map_root)?
            .into_iter()
            .collect())
    }

    /// Computes novelty against the accumulated coverage map.
    ///
    /// Candidate edges are novel exactly when they are absent from the accumulated
    /// map named by `coverage_map_root`.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the accumulated coverage root is missing or
    /// corrupt.
    pub fn accumulated_coverage_delta<I>(
        &self,
        coverage_map_root: ContentHash,
        candidate_edges: I,
    ) -> Result<CampaignCoverageDelta, CasError>
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let accumulated = self.coverage_edge_set(coverage_map_root)?;
        let mut new_edges = Vec::new();
        let mut known_edges = Vec::new();
        for edge in candidate_edges.into_iter().collect::<BTreeSet<_>>() {
            if accumulated.contains(&edge) {
                known_edges.push(edge);
            } else {
                new_edges.push(edge);
            }
        }
        Ok(CampaignCoverageDelta {
            coverage_map_root,
            new_edges,
            known_edges,
        })
    }

    /// Merges two accumulated coverage roots by grow-only set union.
    ///
    /// The operation is commutative, associative, and idempotent because the root
    /// material is the sorted set union of both inputs.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when either root is missing, corrupt, or cannot be
    /// stored.
    pub fn merge_accumulated_coverage_maps(
        &self,
        left: ContentHash,
        right: ContentHash,
    ) -> Result<ContentHash, CasError> {
        let mut edges = self.coverage_edge_set(left)?;
        edges.extend(self.coverage_edge_set(right)?);
        self.persist_coverage_edges(&edges)
    }

    /// Persists a grow-only findings ledger root.
    ///
    /// Finding artifacts are content-addressed before the ledger is written. If
    /// multiple runs rediscover the same finding artifact, the ledger retains
    /// one entry keyed by that artifact's content address.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when a finding artifact, finding entry, or ledger root
    /// cannot be stored.
    pub fn persist_findings_ledger<I>(&self, findings: I) -> Result<ContentHash, CasError>
    where
        I: IntoIterator<Item = CampaignFinding>,
    {
        let mut entries = BTreeMap::new();
        for finding in findings {
            let (artifact_hash, finding_hash) = self.persist_finding(&finding)?;
            insert_deduped_finding_entry(&mut entries, artifact_hash, finding_hash);
        }
        self.persist_findings_entries(&entries)
    }

    /// Returns the sorted persisted findings named by a ledger root.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the ledger or any finding artifact is missing,
    /// corrupt, or not self-validating.
    pub fn findings_ledger_entries(
        &self,
        findings_root: ContentHash,
    ) -> Result<Vec<PersistedCampaignFinding>, CasError> {
        self.findings_entry_map(findings_root)
            .map(|entries| entries.into_values().collect())
    }

    /// Merges two findings ledgers by grow-only set union.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when either ledger root is missing, corrupt, or cannot
    /// be stored.
    pub fn merge_findings_ledgers(
        &self,
        left: ContentHash,
        right: ContentHash,
    ) -> Result<ContentHash, CasError> {
        let mut entries = self.finding_entry_hashes(left)?;
        for (artifact_hash, finding_hash) in self.finding_entry_hashes(right)? {
            insert_deduped_finding_entry(&mut entries, artifact_hash, finding_hash);
        }
        self.persist_findings_entries(&entries)
    }

    /// Returns the campaign garbage-collection roots named by `manifest`.
    ///
    /// The roots are exactly the manifest's corpus, coverage-map, findings, and
    /// genesis pins. The manifest object itself is owned by the mutable head log;
    /// this root set describes the storage graph below that manifest.
    #[must_use]
    pub fn campaign_gc_roots(&self, manifest: &CampaignManifest) -> CampaignGcRoots {
        CampaignGcRoots {
            corpus_root: manifest.corpus_root,
            coverage_map_root: manifest.coverage_map_root,
            findings_root: manifest.findings_root,
            genesis_pin: manifest.genesis_pin,
        }
    }

    /// Plans campaign object garbage collection for a candidate object set.
    ///
    /// Reachability starts at the manifest's corpus, coverage-map, findings, and
    /// genesis roots. Retained corpus replay artifacts and all finding replay
    /// artifacts stay live; candidates outside that closure are returned as
    /// sweep candidates.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when any manifest root is missing, malformed, or
    /// refers to malformed campaign objects.
    pub fn campaign_gc_plan<I>(
        &self,
        manifest: &CampaignManifest,
        candidates: I,
    ) -> Result<CampaignGcPlan, CasError>
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let roots = self.campaign_gc_roots(manifest);
        let retained_objects = self.campaign_reachable_objects(&roots)?;
        let sweep_candidates = candidates
            .into_iter()
            .collect::<BTreeSet<_>>()
            .difference(&retained_objects)
            .copied()
            .collect();
        Ok(CampaignGcPlan {
            roots,
            retained_objects,
            sweep_candidates,
        })
    }

    /// Sweeps unpinned campaign object candidates outside the manifest root closure.
    ///
    /// The caller supplies the candidate set, typically from a store inventory.
    /// This method deletes only candidates that are not reachable from the
    /// manifest roots; retained roots, retained corpus artifacts, and findings
    /// ledger entries are never deleted by this pass.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the reachability plan cannot be computed or a
    /// sweep candidate cannot be removed from the filesystem-backed store.
    pub fn garbage_collect_campaign_candidates<I>(
        &self,
        manifest: &CampaignManifest,
        candidates: I,
    ) -> Result<CampaignGcReport, CasError>
    where
        I: IntoIterator<Item = ContentHash>,
    {
        let plan = self.campaign_gc_plan(manifest, candidates)?;
        let mut swept_objects = BTreeSet::new();
        let mut missing_objects = BTreeSet::new();
        for candidate in &plan.sweep_candidates {
            let path = self.store.object_path(candidate);
            match fs::remove_file(&path) {
                Ok(()) => {
                    swept_objects.insert(*candidate);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    missing_objects.insert(*candidate);
                }
                Err(source) => {
                    return Err(CasError::Io {
                        operation: "remove",
                        path,
                        source,
                    });
                }
            }
        }
        Ok(CampaignGcReport {
            plan,
            swept_objects,
            missing_objects,
        })
    }

    /// Persists a deterministic retained corpus root under `policy`.
    ///
    /// The retained corpus is selected by a stable seeded ordering over the
    /// source corpus entries. The resulting root records the source, cap, seed,
    /// and retained entries so campaign-head advancement can distinguish
    /// authorized pruning from an unproven corpus regression.
    ///
    /// # Errors
    ///
    /// Returns [`CasError`] when the source corpus cannot be read or the retained
    /// root cannot be persisted.
    pub fn retain_campaign_corpus_under_cap(
        &self,
        corpus_root: ContentHash,
        policy: CampaignCorpusRetentionPolicy,
    ) -> Result<CampaignCorpusRetentionReport, CasError> {
        validate_campaign_corpus_retention_policy(&policy, self.store.object_path(&corpus_root))?;
        let source_entries = self.corpus_entry_hashes(corpus_root)?;
        let retained_entries = retain_campaign_corpus_entries(&source_entries, &policy);
        let retained_root =
            self.persist_campaign_corpus_retention(corpus_root, &policy, &retained_entries)?;
        let retained_artifacts = retained_entries.keys().copied().collect::<Vec<_>>();
        let evicted_artifacts = source_entries
            .keys()
            .filter(|artifact_hash| !retained_entries.contains_key(artifact_hash))
            .copied()
            .collect();
        Ok(CampaignCorpusRetentionReport {
            source_root: corpus_root,
            retained_root,
            cap: policy.cap,
            seed: policy.seed,
            retained_artifacts,
            evicted_artifacts,
        })
    }

    fn validate_manifest_roots(&self, manifest: &CampaignManifest) -> Result<(), CasError> {
        self.require_manifest_root("corpus_root", manifest.corpus_root)?;
        self.require_manifest_root("coverage_map_root", manifest.coverage_map_root)?;
        self.require_manifest_root("findings_root", manifest.findings_root)?;
        Ok(())
    }

    fn read_manifest_object(
        &self,
        manifest_hash: ContentHash,
    ) -> Result<CampaignManifest, CasError> {
        let material = String::from_utf8(self.store.get(&manifest_hash)?).map_err(|_| {
            CasError::InvalidCampaignRecord {
                path: self.store.object_path(&manifest_hash),
                reason: "campaign manifest object is not UTF-8",
            }
        })?;
        let manifest = parse_manifest_record(&self.store.object_path(&manifest_hash), &material)?;
        self.validate_manifest_roots(&manifest)?;
        Ok(manifest)
    }

    fn validate_monotone_manifest_advance(
        &self,
        current: &CampaignManifest,
        proposed: &CampaignManifest,
        retention_policy: Option<&CampaignCorpusRetentionPolicy>,
    ) -> Result<(), CasError> {
        validate_campaign_lineage(current, proposed)?;
        self.validate_monotone_root(
            "corpus",
            current.corpus_root,
            proposed.corpus_root,
            retention_policy,
        )?;
        self.validate_monotone_root(
            "coverage-map",
            current.coverage_map_root,
            proposed.coverage_map_root,
            None,
        )?;
        self.validate_monotone_root(
            "findings",
            current.findings_root,
            proposed.findings_root,
            None,
        )?;
        Ok(())
    }

    fn validate_monotone_root(
        &self,
        label: &'static str,
        current: ContentHash,
        proposed: ContentHash,
        retention_policy: Option<&CampaignCorpusRetentionPolicy>,
    ) -> Result<(), CasError> {
        if current == proposed {
            return Ok(());
        }
        if !self.supports_typed_campaign_root(label, current)? {
            return Ok(());
        }
        if !self.supports_typed_campaign_root(label, proposed)? {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&proposed),
                reason: campaign_root_regression_reason(label),
            });
        }
        match label {
            "corpus" => self.validate_campaign_corpus_superset(current, proposed, retention_policy),
            "coverage-map" => self.validate_coverage_superset(current, proposed),
            "findings" => self.validate_findings_superset(current, proposed),
            _ => Ok(()),
        }
    }

    fn validate_campaign_corpus_superset(
        &self,
        current: ContentHash,
        proposed: ContentHash,
        retention_policy: Option<&CampaignCorpusRetentionPolicy>,
    ) -> Result<(), CasError> {
        if self.corpus_retention_record(current)?.is_some() {
            let Some(policy) = retention_policy else {
                return Err(CasError::InvalidCampaignRecord {
                    path: self.store.object_path(&proposed),
                    reason: "campaign corpus retention roots require explicit retention policy",
                });
            };
            return self.validate_campaign_corpus_retention_advance(current, proposed, policy);
        }
        let current_entries = self.corpus_entry_hashes(current)?;
        let proposed_entries = self.corpus_entry_hashes(proposed)?;
        let mut dropped_prior_seed = false;
        for (artifact_hash, replay_hash) in current_entries {
            if proposed_entries.get(&artifact_hash) != Some(&replay_hash) {
                dropped_prior_seed = true;
                break;
            }
        }
        if dropped_prior_seed {
            let Some(policy) = retention_policy else {
                return Err(CasError::InvalidCampaignRecord {
                    path: self.store.object_path(&proposed),
                    reason: "campaign corpus advance would drop a prior seed artifact",
                });
            };
            return self.validate_campaign_corpus_retention_advance(current, proposed, policy);
        }
        Ok(())
    }

    fn validate_campaign_corpus_retention_advance(
        &self,
        current: ContentHash,
        proposed: ContentHash,
        policy: &CampaignCorpusRetentionPolicy,
    ) -> Result<(), CasError> {
        validate_campaign_corpus_retention_policy(policy, self.store.object_path(&proposed))?;
        let Some(retention) = self.corpus_retention_record(proposed)? else {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&proposed),
                reason: "campaign corpus advance would drop a prior seed artifact",
            });
        };
        if retention.policy != *policy {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&proposed),
                reason: "campaign corpus retention policy does not match authorized retention policy",
            });
        }
        if retention.source_root != current {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&proposed),
                reason: "campaign corpus retention source does not match current root",
            });
        }
        let current_entries = self.corpus_entry_hashes(current)?;
        let expected_entries = retain_campaign_corpus_entries(&current_entries, &retention.policy);
        if retention.entries != expected_entries {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&proposed),
                reason: "campaign corpus retention root does not match deterministic seeded cap",
            });
        }
        Ok(())
    }

    fn validate_coverage_superset(
        &self,
        current: ContentHash,
        proposed: ContentHash,
    ) -> Result<(), CasError> {
        let current_edges = self.coverage_edge_set(current)?;
        let proposed_edges = self.coverage_edge_set(proposed)?;
        if !current_edges.is_subset(&proposed_edges) {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&proposed),
                reason: "campaign coverage-map advance would reduce accumulated coverage",
            });
        }
        Ok(())
    }

    fn validate_findings_superset(
        &self,
        current: ContentHash,
        proposed: ContentHash,
    ) -> Result<(), CasError> {
        let current_entries = self.finding_entry_hashes(current)?;
        let proposed_entries = self.finding_entry_hashes(proposed)?;
        for artifact_hash in current_entries.keys() {
            if !proposed_entries.contains_key(artifact_hash) {
                return Err(CasError::InvalidCampaignRecord {
                    path: self.store.object_path(&proposed),
                    reason: "campaign findings advance would drop a prior finding artifact",
                });
            }
        }
        Ok(())
    }

    fn require_manifest_root(
        &self,
        field: &'static str,
        root: ContentHash,
    ) -> Result<(), CasError> {
        if self.store.has(&root)? {
            return Ok(());
        }
        Err(CasError::InvalidCampaignRecord {
            path: self.store.object_path(&root),
            reason: match field {
                "corpus_root" => "campaign corpus root object is missing",
                "coverage_map_root" => "campaign coverage-map root object is missing",
                "findings_root" => "campaign findings root object is missing",
                _ => "campaign manifest root object is missing",
            },
        })
    }

    fn validate_fresh_lineage_roots(
        &self,
        prior: &CampaignManifest,
        fresh_roots: &CampaignFreshLineageRoots,
    ) -> Result<(), CasError> {
        if prior.corpus_root == fresh_roots.corpus_root {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.corpus_root),
                reason: "fresh campaign lineage must use a new corpus root",
            });
        }
        if prior.coverage_map_root == fresh_roots.coverage_map_root {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.coverage_map_root),
                reason: "fresh campaign lineage must use a new coverage-map root",
            });
        }
        if prior.findings_root == fresh_roots.findings_root {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.findings_root),
                reason: "fresh campaign lineage must use a new findings root",
            });
        }
        if prior.genesis_pin == fresh_roots.genesis_pin {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.genesis_pin),
                reason: "fresh campaign lineage must use a new genesis pin",
            });
        }
        if !self.supports_typed_campaign_root("corpus", fresh_roots.corpus_root)? {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.corpus_root),
                reason: "fresh campaign lineage corpus root is not a typed corpus root",
            });
        }
        if !self.supports_typed_campaign_root("coverage-map", fresh_roots.coverage_map_root)? {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.coverage_map_root),
                reason: "fresh campaign lineage coverage-map root is not a typed coverage root",
            });
        }
        if !self.supports_typed_campaign_root("findings", fresh_roots.findings_root)? {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.findings_root),
                reason: "fresh campaign lineage findings root is not a typed findings root",
            });
        }
        if !self.store.has(&fresh_roots.genesis_pin)? {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.genesis_pin),
                reason: "fresh campaign lineage genesis pin is missing",
            });
        }

        let prior_corpus = self.corpus_entry_hashes(prior.corpus_root)?;
        let fresh_corpus = self.corpus_entry_hashes(fresh_roots.corpus_root)?;
        if fresh_corpus
            .keys()
            .any(|artifact_hash| prior_corpus.contains_key(artifact_hash))
        {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.corpus_root),
                reason: "fresh campaign lineage corpus must not reuse prior corpus entries",
            });
        }

        let prior_coverage = self.coverage_edge_set(prior.coverage_map_root)?;
        let fresh_coverage = self.coverage_edge_set(fresh_roots.coverage_map_root)?;
        if fresh_coverage
            .iter()
            .any(|edge| prior_coverage.contains(edge))
        {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.coverage_map_root),
                reason: "fresh campaign lineage coverage must not reuse prior coverage edges",
            });
        }

        let prior_findings = self.finding_entry_hashes(prior.findings_root)?;
        let fresh_findings = self.finding_entry_hashes(fresh_roots.findings_root)?;
        if fresh_findings
            .keys()
            .any(|artifact_hash| prior_findings.contains_key(artifact_hash))
        {
            return Err(CasError::InvalidCampaignRecord {
                path: self.store.object_path(&fresh_roots.findings_root),
                reason: "fresh campaign lineage findings must not reuse prior finding artifacts",
            });
        }

        Ok(())
    }

    fn install_fresh_lineage_head(
        &self,
        prior: &CampaignManifest,
        fresh_manifest_hash: ContentHash,
    ) -> Result<(), CasError> {
        let mut guard = self.acquire_head_lock(FlockOperation::LockExclusive)?;
        let current_pointer = self.read_head_pointer()?;
        let Some(pointer) = current_pointer else {
            return Err(CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "fresh campaign lineage requires prior manifest to be current head",
            });
        };
        let current_manifest = self.read_manifest_object(pointer.manifest_hash)?;
        if current_manifest != *prior {
            return Err(CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "fresh campaign lineage requires prior manifest to be current head",
            });
        }
        let current_pointer = Some(pointer);
        self.write_head(&mut guard, current_pointer, fresh_manifest_hash)
    }

    fn require_fresh_lineage_current_head(&self, prior: &CampaignManifest) -> Result<(), CasError> {
        let Some(pointer) = self.read_head_pointer()? else {
            return Err(CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "fresh campaign lineage requires prior manifest to be current head",
            });
        };
        let current_manifest = self.read_manifest_object(pointer.manifest_hash)?;
        if current_manifest != *prior {
            return Err(CasError::InvalidCampaignRecord {
                path: self.head_path(),
                reason: "fresh campaign lineage requires prior manifest to be current head",
            });
        }
        Ok(())
    }

    fn merge_manifests(
        &self,
        current: &CampaignManifest,
        proposed: &CampaignManifest,
    ) -> Result<CampaignManifest, CasError> {
        validate_campaign_lineage(current, proposed)?;
        Ok(CampaignManifest {
            corpus_root: self.merge_manifest_root(
                "corpus",
                current.corpus_root,
                proposed.corpus_root,
            )?,
            coverage_map_root: self.merge_manifest_root(
                "coverage-map",
                current.coverage_map_root,
                proposed.coverage_map_root,
            )?,
            findings_root: self.merge_manifest_root(
                "findings",
                current.findings_root,
                proposed.findings_root,
            )?,
            genesis_pin: current.genesis_pin,
            provenance: current.provenance.clone(),
        })
    }

    fn merge_manifest_root(
        &self,
        label: &'static str,
        left: ContentHash,
        right: ContentHash,
    ) -> Result<ContentHash, CasError> {
        self.require_manifest_root(campaign_root_field(label), left)?;
        self.require_manifest_root(campaign_root_field(label), right)?;
        if left == right {
            return Ok(left);
        }
        if let Some(merged) = self.try_merge_typed_manifest_root(label, left, right)? {
            return Ok(merged);
        }
        let (first, second) = ordered_manifest_roots(left, right);
        let merged = self
            .store
            .put(campaign_root_merge_record_material(label, first, second).as_bytes())?;
        debug_assert_eq!(merged, campaign_root_merge_hash(label, left, right));
        Ok(merged)
    }

    fn try_merge_typed_manifest_root(
        &self,
        label: &'static str,
        left: ContentHash,
        right: ContentHash,
    ) -> Result<Option<ContentHash>, CasError> {
        if !self.supports_typed_campaign_root(label, left)?
            || !self.supports_typed_campaign_root(label, right)?
        {
            return Ok(None);
        }
        let merged = match label {
            "corpus" => {
                if self.corpus_retention_record(left)?.is_some()
                    || self.corpus_retention_record(right)?.is_some()
                {
                    return Err(CasError::InvalidCampaignRecord {
                        path: self.store.object_path(&right),
                        reason: "campaign corpus retention roots require explicit retention policy",
                    });
                }
                let mut entries = self.corpus_entry_hashes(left)?;
                entries.extend(self.corpus_entry_hashes(right)?);
                self.persist_campaign_corpus_entries(&entries)?
            }
            "coverage-map" => self.merge_accumulated_coverage_maps(left, right)?,
            "findings" => self.merge_findings_ledgers(left, right)?,
            _ => return Ok(None),
        };
        Ok(Some(merged))
    }

    fn supports_typed_campaign_root(
        &self,
        label: &'static str,
        root: ContentHash,
    ) -> Result<bool, CasError> {
        let material = self.read_campaign_object_text(root)?;
        let format = record_format(&material);
        if matches!(format, Some(format) if is_typed_campaign_root_format(label, format)) {
            return Ok(true);
        }
        if format != Some("crucible.campaign-root-merge.v1") {
            return Ok(false);
        }
        let merge = parse_campaign_root_merge_record(&self.store.object_path(&root), &material)?;
        if merge.label != label {
            return Ok(false);
        }
        Ok(self.supports_typed_campaign_root(label, merge.left)?
            && self.supports_typed_campaign_root(label, merge.right)?)
    }

    fn campaign_reachable_objects(
        &self,
        roots: &CampaignGcRoots,
    ) -> Result<BTreeSet<ContentHash>, CasError> {
        let mut retained = BTreeSet::from([roots.genesis_pin]);
        self.collect_campaign_root_closure("corpus", roots.corpus_root, &mut retained)?;
        self.collect_campaign_root_closure("coverage-map", roots.coverage_map_root, &mut retained)?;
        self.collect_campaign_root_closure("findings", roots.findings_root, &mut retained)?;
        Ok(retained)
    }

    fn collect_campaign_root_closure(
        &self,
        label: &'static str,
        root: ContentHash,
        retained: &mut BTreeSet<ContentHash>,
    ) -> Result<(), CasError> {
        if !retained.insert(root) {
            return Ok(());
        }
        let material = self.read_campaign_object_text(root)?;
        let path = self.store.object_path(&root);
        match record_format(&material) {
            Some("crucible.campaign-root-merge.v1") => {
                let merge = parse_campaign_root_merge_record(&path, &material)?;
                if merge.label != label {
                    return Err(CasError::InvalidCampaignRecord {
                        path,
                        reason: "campaign root merge label does not match manifest field",
                    });
                }
                self.collect_campaign_root_closure(label, merge.left, retained)?;
                self.collect_campaign_root_closure(label, merge.right, retained)
            }
            Some("crucible.campaign-corpus.v1") | Some("crucible.campaign-corpus-retention.v1")
                if label == "corpus" =>
            {
                for artifact_hash in self.corpus_entry_hashes(root)?.keys() {
                    retained.insert(*artifact_hash);
                }
                Ok(())
            }
            Some("crucible.campaign-coverage-map.v1") if label == "coverage-map" => {
                retained.extend(self.coverage_edge_set(root)?);
                Ok(())
            }
            Some("crucible.campaign-findings-ledger.v1") if label == "findings" => {
                for (artifact_hash, finding_hash) in self.finding_entry_hashes(root)? {
                    retained.insert(artifact_hash);
                    retained.insert(finding_hash);
                }
                Ok(())
            }
            _ => Err(CasError::InvalidCampaignRecord {
                path,
                reason: "campaign manifest root format is unsupported for GC",
            }),
        }
    }

    fn persist_campaign_corpus_entries(
        &self,
        entries: &BTreeMap<ContentHash, ContentHash>,
    ) -> Result<ContentHash, CasError> {
        self.store
            .put(campaign_corpus_record_material(entries).as_bytes())
    }

    fn persist_campaign_corpus_retention(
        &self,
        source_root: ContentHash,
        policy: &CampaignCorpusRetentionPolicy,
        entries: &BTreeMap<ContentHash, ContentHash>,
    ) -> Result<ContentHash, CasError> {
        self.store
            .put(campaign_corpus_retention_record_material(source_root, policy, entries).as_bytes())
    }

    fn persist_coverage_edges(
        &self,
        edges: &BTreeSet<ContentHash>,
    ) -> Result<ContentHash, CasError> {
        self.store
            .put(campaign_coverage_map_record_material(edges).as_bytes())
    }

    fn persist_finding(
        &self,
        finding: &CampaignFinding,
    ) -> Result<(ContentHash, ContentHash), CasError> {
        let artifact_hash = self.persist_replay_artifact(&finding.artifact)?;
        let finding_hash = self
            .store
            .put(campaign_finding_record_material(finding, artifact_hash).as_bytes())?;
        Ok((artifact_hash, finding_hash))
    }

    fn persist_findings_entries(
        &self,
        entries: &BTreeMap<ContentHash, ContentHash>,
    ) -> Result<ContentHash, CasError> {
        self.store
            .put(campaign_findings_ledger_record_material(entries).as_bytes())
    }

    fn corpus_seed_map(
        &self,
        root: ContentHash,
    ) -> Result<BTreeMap<ContentHash, CampaignCorpusSeed>, CasError> {
        let entries = self.corpus_entry_hashes(root)?;
        let mut seeds = BTreeMap::new();
        for (artifact_hash, expected_replay_hash) in entries {
            let artifact = self.read_replay_artifact(artifact_hash)?;
            let replay_hash = artifact.replay_hash();
            if replay_hash != expected_replay_hash {
                return Err(CasError::InvalidCampaignRecord {
                    path: self.store.object_path(&artifact_hash),
                    reason: "campaign corpus replay hash does not match artifact",
                });
            }
            seeds.insert(
                artifact_hash,
                CampaignCorpusSeed {
                    artifact_hash,
                    replay_hash,
                    artifact,
                },
            );
        }
        Ok(seeds)
    }

    fn corpus_entry_hashes(
        &self,
        root: ContentHash,
    ) -> Result<BTreeMap<ContentHash, ContentHash>, CasError> {
        let material = self.read_campaign_object_text(root)?;
        let path = self.store.object_path(&root);
        match record_format(&material) {
            Some("crucible.campaign-corpus.v1") => parse_campaign_corpus_record(&path, &material),
            Some("crucible.campaign-corpus-retention.v1") => {
                parse_campaign_corpus_retention_record(&path, &material)
                    .map(|retention| retention.entries)
            }
            Some("crucible.campaign-root-merge.v1") => {
                let merge = parse_campaign_root_merge_record(&path, &material)?;
                if merge.label != "corpus" {
                    return Err(CasError::InvalidCampaignRecord {
                        path,
                        reason: "campaign root merge label is not corpus",
                    });
                }
                let mut entries = self.corpus_entry_hashes(merge.left)?;
                entries.extend(self.corpus_entry_hashes(merge.right)?);
                Ok(entries)
            }
            _ => Err(CasError::InvalidCampaignRecord {
                path,
                reason: "campaign corpus root format is unsupported",
            }),
        }
    }

    fn corpus_retention_record(
        &self,
        root: ContentHash,
    ) -> Result<Option<CampaignCorpusRetentionRecord>, CasError> {
        let material = self.read_campaign_object_text(root)?;
        if record_format(&material) != Some("crucible.campaign-corpus-retention.v1") {
            return Ok(None);
        }
        parse_campaign_corpus_retention_record(&self.store.object_path(&root), &material).map(Some)
    }

    fn coverage_edge_set(&self, root: ContentHash) -> Result<BTreeSet<ContentHash>, CasError> {
        let material = self.read_campaign_object_text(root)?;
        let path = self.store.object_path(&root);
        match record_format(&material) {
            Some("crucible.campaign-coverage-map.v1") => {
                parse_campaign_coverage_map_record(&path, &material)
            }
            Some("crucible.campaign-root-merge.v1") => {
                let merge = parse_campaign_root_merge_record(&path, &material)?;
                if merge.label != "coverage-map" {
                    return Err(CasError::InvalidCampaignRecord {
                        path,
                        reason: "campaign root merge label is not coverage-map",
                    });
                }
                let mut entries = self.coverage_edge_set(merge.left)?;
                entries.extend(self.coverage_edge_set(merge.right)?);
                Ok(entries)
            }
            _ => Err(CasError::InvalidCampaignRecord {
                path,
                reason: "campaign coverage-map root format is unsupported",
            }),
        }
    }

    fn findings_entry_map(
        &self,
        root: ContentHash,
    ) -> Result<BTreeMap<ContentHash, PersistedCampaignFinding>, CasError> {
        let entries = self.finding_entry_hashes(root)?;
        let mut findings = BTreeMap::new();
        for (artifact_hash, finding_hash) in entries {
            let material = self.read_campaign_object_text(finding_hash)?;
            let persisted = parse_campaign_finding_record(
                &self.store.object_path(&finding_hash),
                finding_hash,
                &material,
            )?;
            if persisted.artifact_hash != artifact_hash {
                return Err(CasError::InvalidCampaignRecord {
                    path: self.store.object_path(&finding_hash),
                    reason: "campaign findings ledger artifact does not match finding record",
                });
            }
            let artifact = self.read_replay_artifact(persisted.artifact_hash)?;
            if persisted.replay_hash != artifact.replay_hash() {
                return Err(CasError::InvalidCampaignRecord {
                    path: self.store.object_path(&finding_hash),
                    reason: "campaign finding replay hash does not match artifact",
                });
            }
            findings.insert(finding_hash, persisted);
        }
        Ok(findings)
    }

    fn finding_entry_hashes(
        &self,
        root: ContentHash,
    ) -> Result<BTreeMap<ContentHash, ContentHash>, CasError> {
        let material = self.read_campaign_object_text(root)?;
        let path = self.store.object_path(&root);
        match record_format(&material) {
            Some("crucible.campaign-findings-ledger.v1") => {
                parse_campaign_findings_ledger_record(&path, &material)
            }
            Some("crucible.campaign-root-merge.v1") => {
                let merge = parse_campaign_root_merge_record(&path, &material)?;
                if merge.label != "findings" {
                    return Err(CasError::InvalidCampaignRecord {
                        path,
                        reason: "campaign root merge label is not findings",
                    });
                }
                let mut entries = self.finding_entry_hashes(merge.left)?;
                for (artifact_hash, finding_hash) in self.finding_entry_hashes(merge.right)? {
                    insert_deduped_finding_entry(&mut entries, artifact_hash, finding_hash);
                }
                Ok(entries)
            }
            _ => Err(CasError::InvalidCampaignRecord {
                path,
                reason: "campaign findings root format is unsupported",
            }),
        }
    }

    fn read_campaign_object_text(&self, key: ContentHash) -> Result<String, CasError> {
        String::from_utf8(self.store.get(&key)?).map_err(|_| CasError::InvalidCampaignRecord {
            path: self.store.object_path(&key),
            reason: "campaign object is not UTF-8",
        })
    }

    fn acquire_head_lock(&self, operation: FlockOperation) -> Result<CampaignHeadLock, CasError> {
        let path = self.head_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| CasError::Io {
                operation: "create-dir",
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|source| CasError::Io {
                operation: "open",
                path: path.clone(),
                source,
            })?;
        flock(&file, operation).map_err(|source| CasError::Io {
            operation: "lock",
            path,
            source: source.into(),
        })?;
        Ok(CampaignHeadLock { file })
    }

    fn read_head_hash(&self) -> Result<Option<ContentHash>, CasError> {
        Ok(self
            .read_head_pointer()?
            .map(|pointer| pointer.manifest_hash))
    }

    fn read_head_pointer(&self) -> Result<Option<CampaignHeadPointer>, CasError> {
        let path = self.head_path();
        let material = match fs::read_to_string(&path) {
            Ok(material) => material,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(CasError::Io {
                    operation: "read",
                    path,
                    source,
                });
            }
        };
        if material.trim().is_empty() {
            return Ok(None);
        }
        parse_campaign_head_record(&path, &material)
    }

    fn write_head(
        &self,
        lock: &mut CampaignHeadLock,
        current: Option<CampaignHeadPointer>,
        manifest_hash: ContentHash,
    ) -> Result<(), CasError> {
        let path = self.head_path();
        let next_generation = current
            .map(|pointer| pointer.generation)
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| CasError::InvalidCampaignRecord {
                path: path.clone(),
                reason: "campaign head generation overflows u64",
            })?;
        let metadata = lock.file.metadata().map_err(|source| CasError::Io {
            operation: "stat",
            path: path.clone(),
            source,
        })?;
        lock.file
            .seek(SeekFrom::End(0))
            .map_err(|source| CasError::Io {
                operation: "seek",
                path: path.clone(),
                source,
            })?;
        if metadata.len() != 0 {
            lock.file
                .seek(SeekFrom::End(-1))
                .map_err(|source| CasError::Io {
                    operation: "seek",
                    path: path.clone(),
                    source,
                })?;
            let mut last_byte = [0_u8; 1];
            lock.file
                .read_exact(&mut last_byte)
                .map_err(|source| CasError::Io {
                    operation: "read",
                    path: path.clone(),
                    source,
                })?;
            lock.file
                .seek(SeekFrom::End(0))
                .map_err(|source| CasError::Io {
                    operation: "seek",
                    path: path.clone(),
                    source,
                })?;
            if last_byte != [b'\n'] {
                lock.file.write_all(b"\n").map_err(|source| CasError::Io {
                    operation: "write",
                    path: path.clone(),
                    source,
                })?;
            }
        }
        lock.file
            .write_all(campaign_head_entry_material(next_generation, manifest_hash).as_bytes())
            .map_err(|source| CasError::Io {
                operation: "write",
                path: path.clone(),
                source,
            })?;
        lock.file.sync_data().map_err(|source| CasError::Io {
            operation: "sync",
            path,
            source,
        })
    }
}

#[derive(Debug)]
struct CampaignHeadLock {
    file: fs::File,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CampaignHeadPointer {
    generation: u64,
    manifest_hash: ContentHash,
}

/// Immutable manifest named by a persistent campaign head.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CampaignManifest {
    /// Root of the retained campaign corpus set.
    pub corpus_root: ContentHash,
    /// Root of the accumulated coverage map.
    pub coverage_map_root: ContentHash,
    /// Root of the campaign findings ledger.
    pub findings_root: ContentHash,
    /// Baked genesis checkpoint pin for this lineage.
    pub genesis_pin: ContentHash,
    /// Provenance triple that owns this campaign lineage.
    pub provenance: CampaignProvenance,
}

impl CampaignManifest {
    /// Builds a campaign manifest from content-addressed roots.
    #[must_use]
    pub fn new(
        corpus_root: ContentHash,
        coverage_map_root: ContentHash,
        findings_root: ContentHash,
        genesis_pin: ContentHash,
        provenance: CampaignProvenance,
    ) -> Self {
        Self {
            corpus_root,
            coverage_map_root,
            findings_root,
            genesis_pin,
            provenance,
        }
    }
}

/// Provenance triple recorded in a campaign manifest.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CampaignProvenance {
    /// Crucible software version.
    pub crucible_version: String,
    /// QEMU build identity plus applied series hash.
    pub qemu_build: String,
    /// Combined shmem, guest-host channel, and RPC ABI versions.
    pub abi_versions: String,
}

impl CampaignProvenance {
    /// Builds a campaign provenance triple.
    #[must_use]
    pub fn new(
        crucible_version: impl Into<String>,
        qemu_build: impl Into<String>,
        abi_versions: impl Into<String>,
    ) -> Self {
        Self {
            crucible_version: crucible_version.into(),
            qemu_build: qemu_build.into(),
            abi_versions: abi_versions.into(),
        }
    }
}

/// Computes the content-addressed key for a campaign provenance triple.
///
/// # Errors
///
/// Returns [`CasError`] when any provenance field is empty or contains a
/// newline.
pub fn campaign_provenance_key(provenance: &CampaignProvenance) -> Result<ContentHash, CasError> {
    validate_campaign_provenance(provenance)?;
    Ok(ContentHash::from_bytes(
        campaign_provenance_material(provenance).as_bytes(),
    ))
}

/// Computes the deterministic lineage id for a campaign manifest.
///
/// The lineage id is keyed to the manifest's genesis pin and provenance key, not
/// to the mutable corpus, coverage, or findings roots that advance over time.
///
/// # Errors
///
/// Returns [`CasError`] when the manifest or provenance fields are invalid.
pub fn campaign_lineage_id(manifest: &CampaignManifest) -> Result<ContentHash, CasError> {
    validate_campaign_manifest(manifest)?;
    let provenance_key = campaign_provenance_key(&manifest.provenance)?;
    Ok(ContentHash::from_bytes(
        campaign_lineage_material(manifest, provenance_key).as_bytes(),
    ))
}

/// Current content-addressed campaign manifest head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignHead {
    /// Content hash of the manifest object.
    pub manifest_hash: ContentHash,
    /// Parsed immutable manifest object.
    pub manifest: CampaignManifest,
}

/// Result of a campaign manifest-head compare-and-swap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignCasOutcome {
    /// The head was advanced to the supplied manifest.
    Advanced(CampaignHead),
    /// The head changed before the compare-and-swap could publish the proposal.
    LostUpdate {
        /// Head hash expected by the caller.
        expected: Option<ContentHash>,
        /// Current head hash observed during CAS.
        current: Option<ContentHash>,
        /// Content-addressed proposal retained in the store.
        proposed_manifest_hash: ContentHash,
    },
}

/// Report from read-merge-retry campaign-head advancement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignAdvanceReport {
    /// Number of CAS attempts made.
    pub attempts: usize,
    /// Final advanced campaign head.
    pub head: CampaignHead,
}

/// Self-contained campaign replay artifact.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CampaignReplayArtifact {
    definition: Vec<u8>,
    seed: Vec<u8>,
    schedule: Vec<u8>,
}

impl CampaignReplayArtifact {
    /// Builds a replay artifact from definition, seed, and schedule bytes.
    #[must_use]
    pub fn new(
        definition: impl Into<Vec<u8>>,
        seed: impl Into<Vec<u8>>,
        schedule: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            definition: definition.into(),
            seed: seed.into(),
            schedule: schedule.into(),
        }
    }

    /// Returns the scenario or workload definition bytes.
    #[must_use]
    pub fn definition(&self) -> &[u8] {
        &self.definition
    }

    /// Returns the deterministic seed bytes.
    #[must_use]
    pub fn seed(&self) -> &[u8] {
        &self.seed
    }

    /// Returns the deterministic schedule bytes.
    #[must_use]
    pub fn schedule(&self) -> &[u8] {
        &self.schedule
    }

    /// Returns the canonical replay-input bytes produced from the artifact.
    #[must_use]
    pub fn replay_bytes(&self) -> Vec<u8> {
        campaign_replay_input_material(self).into_bytes()
    }

    /// Returns the content hash of the canonical replay input.
    #[must_use]
    pub fn replay_hash(&self) -> ContentHash {
        ContentHash::from_bytes(&self.replay_bytes())
    }
}

/// Corpus seed loaded for the next campaign run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignCorpusSeed {
    /// Content hash of the self-contained replay artifact.
    pub artifact_hash: ContentHash,
    /// Replay hash recorded by the corpus root.
    pub replay_hash: ContentHash,
    /// Self-contained replay artifact bytes.
    pub artifact: CampaignReplayArtifact,
}

impl CampaignCorpusSeed {
    /// Returns whether the loaded artifact reproduces the recorded replay hash.
    #[must_use]
    pub fn reproduces_bit_identically(&self) -> bool {
        self.artifact.replay_hash() == self.replay_hash
    }
}

/// Provenance-aware decision for campaign run N+1 seeding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignContinuitySeedDecision {
    /// The prior campaign corpus may seed this run.
    SeedPriorCorpus {
        /// Self-contained corpus entries loaded from the prior manifest root.
        seeds: Vec<CampaignCorpusSeed>,
        /// Stable id of the existing campaign lineage.
        lineage_id: ContentHash,
        /// Provenance key shared by the prior corpus and this run.
        provenance_key: ContentHash,
    },
    /// The prior corpus was refused and a fresh lineage baseline was recorded.
    RefuseCrossProvenanceReuse(Box<CampaignFreshLineageBaselineEvent>),
}

impl CampaignContinuitySeedDecision {
    /// Returns whether this decision seeds the prior corpus.
    #[must_use]
    pub fn seeds_prior_corpus(&self) -> bool {
        matches!(self, Self::SeedPriorCorpus { .. })
    }

    /// Returns whether this decision refused cross-provenance reuse.
    #[must_use]
    pub fn refuses_cross_provenance_reuse(&self) -> bool {
        matches!(self, Self::RefuseCrossProvenanceReuse(_))
    }
}

/// Baseline event recorded when a campaign forks a fresh lineage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignFreshLineageBaselineEvent {
    /// Content-addressed event record persisted in the campaign object store.
    pub baseline_event_hash: ContentHash,
    /// Event schema identifier.
    pub schema_version: String,
    /// Loud refusal reason for operators and CI logs.
    pub reason: String,
    /// Prior corpus root refused as a seed.
    pub refused_corpus_root: ContentHash,
    /// Previous campaign lineage id.
    pub previous_lineage_id: ContentHash,
    /// Fresh campaign lineage id.
    pub fresh_lineage_id: ContentHash,
    /// Provenance key for the refused prior campaign.
    pub previous_provenance_key: ContentHash,
    /// Provenance key for the current run.
    pub run_provenance_key: ContentHash,
    /// Content-addressed manifest object for the fresh lineage.
    pub fresh_manifest_hash: ContentHash,
    /// Fresh immutable manifest persisted for the new lineage.
    pub fresh_manifest: CampaignManifest,
}

/// Novelty result for a candidate against accumulated campaign coverage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignCoverageDelta {
    /// Accumulated coverage root used as the novelty baseline.
    pub coverage_map_root: ContentHash,
    /// Candidate edges absent from the accumulated map.
    pub new_edges: Vec<ContentHash>,
    /// Candidate edges already present in the accumulated map.
    pub known_edges: Vec<ContentHash>,
}

impl CampaignCoverageDelta {
    /// Returns whether the candidate adds campaign-lifetime coverage.
    #[must_use]
    pub fn is_novel(&self) -> bool {
        !self.new_edges.is_empty()
    }
}

/// A finding to add to a cross-run campaign ledger.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CampaignFinding {
    /// Content-addressed failure fingerprint.
    pub fingerprint: ContentHash,
    /// Self-contained reproduction artifact for the finding.
    pub artifact: CampaignReplayArtifact,
}

impl CampaignFinding {
    /// Builds a campaign finding from a fingerprint and replay artifact.
    #[must_use]
    pub fn new(fingerprint: ContentHash, artifact: CampaignReplayArtifact) -> Self {
        Self {
            fingerprint,
            artifact,
        }
    }
}

/// Finding entry loaded from a cross-run campaign ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedCampaignFinding {
    /// Content hash of the finding entry.
    pub finding_hash: ContentHash,
    /// Content-addressed failure fingerprint.
    pub fingerprint: ContentHash,
    /// Content hash of the self-contained replay artifact.
    pub artifact_hash: ContentHash,
    /// Replay hash recorded by the finding entry.
    pub replay_hash: ContentHash,
}

impl PersistedCampaignFinding {
    /// Returns whether `artifact` reproduces the recorded replay hash.
    #[must_use]
    pub fn reproduces_bit_identically(&self, artifact: &CampaignReplayArtifact) -> bool {
        artifact.replay_hash() == self.replay_hash
    }
}

/// Root set for campaign object garbage collection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcRoots {
    /// Root of the retained campaign corpus.
    pub corpus_root: ContentHash,
    /// Root of the accumulated campaign coverage map.
    pub coverage_map_root: ContentHash,
    /// Root of the grow-only findings ledger.
    pub findings_root: ContentHash,
    /// Genesis checkpoint pin for this campaign lineage.
    pub genesis_pin: ContentHash,
}

impl CampaignGcRoots {
    /// Returns the manifest root hashes as a sorted set.
    #[must_use]
    pub fn root_set(&self) -> BTreeSet<ContentHash> {
        BTreeSet::from([
            self.corpus_root,
            self.coverage_map_root,
            self.findings_root,
            self.genesis_pin,
        ])
    }
}

/// New roots used when provenance drift forks a fresh campaign lineage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignFreshLineageRoots {
    /// Fresh retained corpus root for the new lineage.
    pub corpus_root: ContentHash,
    /// Fresh accumulated coverage root for the new lineage.
    pub coverage_map_root: ContentHash,
    /// Fresh findings ledger root for the new lineage.
    pub findings_root: ContentHash,
    /// Fresh genesis checkpoint pin for the new lineage.
    pub genesis_pin: ContentHash,
}

impl CampaignFreshLineageRoots {
    /// Builds a fresh-lineage root set.
    #[must_use]
    pub fn new(
        corpus_root: ContentHash,
        coverage_map_root: ContentHash,
        findings_root: ContentHash,
        genesis_pin: ContentHash,
    ) -> Self {
        Self {
            corpus_root,
            coverage_map_root,
            findings_root,
            genesis_pin,
        }
    }
}

/// Planned campaign garbage-collection result before deletion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcPlan {
    /// Manifest roots used for reachability.
    pub roots: CampaignGcRoots,
    /// Objects retained by root-to-object reachability.
    pub retained_objects: BTreeSet<ContentHash>,
    /// Candidate objects outside the retained closure.
    pub sweep_candidates: BTreeSet<ContentHash>,
}

/// Report from sweeping unpinned campaign object candidates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignGcReport {
    /// Reachability plan used by the sweep.
    pub plan: CampaignGcPlan,
    /// Candidate objects removed from the object store.
    pub swept_objects: BTreeSet<ContentHash>,
    /// Sweep candidates that were already absent.
    pub missing_objects: BTreeSet<ContentHash>,
}

/// Deterministic seeded retention policy for a campaign corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CampaignCorpusRetentionPolicy {
    /// Maximum number of replay artifacts to retain.
    pub cap: usize,
    /// Seed controlling the deterministic artifact ordering.
    pub seed: ContentHash,
}

impl CampaignCorpusRetentionPolicy {
    /// Builds a retention policy from a maximum retained artifact count and seed.
    #[must_use]
    pub fn new(cap: usize, seed: ContentHash) -> Self {
        Self { cap, seed }
    }
}

/// Result of applying deterministic seeded retention to a campaign corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignCorpusRetentionReport {
    /// Source corpus root that was pruned.
    pub source_root: ContentHash,
    /// New retained corpus root containing source, cap, seed, and retained entries.
    pub retained_root: ContentHash,
    /// Maximum number of artifacts retained.
    pub cap: usize,
    /// Seed used for deterministic pruning.
    pub seed: ContentHash,
    /// Artifact hashes retained in the bounded corpus.
    pub retained_artifacts: Vec<ContentHash>,
    /// Artifact hashes evicted from the bounded corpus.
    pub evicted_artifacts: Vec<ContentHash>,
}

/// Campaign checkpoint cache state used to model fat-to-thin eviction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CampaignCheckpointMaterialization {
    /// Content-addressed checkpoint identity and denoted state.
    pub checkpoint: ContentHash,
    /// Thin-source parent checkpoint.
    pub parent: ContentHash,
    /// Thin-source schedule delta from the parent.
    pub schedule_delta: ContentHash,
    /// Optional cache-only exact materialization for a fat checkpoint.
    pub materialization: Option<ContentHash>,
}

impl CampaignCheckpointMaterialization {
    /// Builds a fat checkpoint cache entry.
    #[must_use]
    pub fn fat(
        checkpoint: ContentHash,
        parent: ContentHash,
        schedule_delta: ContentHash,
        materialization: ContentHash,
    ) -> Self {
        Self {
            checkpoint,
            parent,
            schedule_delta,
            materialization: Some(materialization),
        }
    }

    /// Builds a thin checkpoint source entry.
    #[must_use]
    pub fn thin(checkpoint: ContentHash, parent: ContentHash, schedule_delta: ContentHash) -> Self {
        Self {
            checkpoint,
            parent,
            schedule_delta,
            materialization: None,
        }
    }

    /// Evicts a fat checkpoint cache entry to its thin source.
    ///
    /// The checkpoint identity, parent, and schedule delta are preserved. Only
    /// the optional materialization cache is removed.
    #[must_use]
    pub fn evict_to_thin(&self) -> CampaignCheckpointEviction {
        CampaignCheckpointEviction {
            before: self.clone(),
            after: Self::thin(self.checkpoint, self.parent, self.schedule_delta),
            evicted_materialization: self.materialization,
        }
    }
}

/// Before/after record for one campaign fat-to-thin eviction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CampaignCheckpointEviction {
    /// Checkpoint cache entry before eviction.
    pub before: CampaignCheckpointMaterialization,
    /// Thin checkpoint source after eviction.
    pub after: CampaignCheckpointMaterialization,
    /// Cache-only materialization removed by eviction.
    pub evicted_materialization: Option<ContentHash>,
}

impl CampaignCheckpointEviction {
    /// Returns whether the eviction preserved checkpoint value and thin source.
    #[must_use]
    pub fn preserves_value(&self) -> bool {
        self.before.checkpoint == self.after.checkpoint
            && self.before.parent == self.after.parent
            && self.before.schedule_delta == self.after.schedule_delta
            && self.after.materialization.is_none()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CampaignCorpusRetentionRecord {
    source_root: ContentHash,
    policy: CampaignCorpusRetentionPolicy,
    entries: BTreeMap<ContentHash, ContentHash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CampaignRootMerge {
    label: &'static str,
    left: ContentHash,
    right: ContentHash,
}

fn content_path(root: &Path, key: &ContentHash) -> PathBuf {
    let hex = key.to_hex();
    root.join(&hex[0..2]).join(hex)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn validate_claim_request(request: &FrontierClaimRequest) -> Result<(), CasError> {
    if request.host_id.is_empty() {
        return Err(CasError::InvalidLease {
            reason: "host id must not be empty",
        });
    }
    if request.host_id.contains('\n') {
        return Err(CasError::InvalidLease {
            reason: "host id must not contain newlines",
        });
    }
    if request.ttl_ticks == 0 {
        return Err(CasError::InvalidLease {
            reason: "ttl must be greater than zero",
        });
    }
    request
        .now_tick
        .checked_add(request.ttl_ticks)
        .ok_or(CasError::InvalidLease {
            reason: "lease expiry tick overflows u64",
        })?;
    Ok(())
}

fn create_content_record(path: &Path, material: &str) -> Result<bool, CasError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| CasError::Io {
            operation: "create-dir",
            path: parent.to_path_buf(),
            source,
        })?;
    }
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            if let Err(source) = file.write_all(material.as_bytes()) {
                let _ = fs::remove_file(path);
                return Err(CasError::Io {
                    operation: "write",
                    path: path.to_path_buf(),
                    source,
                });
            }
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(source) => Err(CasError::Io {
            operation: "create",
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn coverage_record_material(coverage_fingerprint: &ContentHash, entry: &ContentHash) -> String {
    format!(
        "format=crucible.coverage-map-entry.v1\ncoverage_fingerprint={}\nentry={}\n",
        coverage_fingerprint.to_hex(),
        entry.to_hex()
    )
}

fn coverage_fingerprint_record_material(
    coverage_fingerprint: &ContentHash,
    entries: &[ContentHash],
) -> String {
    let entries = entries
        .iter()
        .map(|entry| entry.to_hex())
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "format=crucible.coverage-fingerprint.v1\ncoverage_fingerprint={}\nentries={entries}\n",
        coverage_fingerprint.to_hex()
    )
}

fn reduction_record_material(fingerprint: &ContentHash, representative: &ContentHash) -> String {
    format!(
        "format=crucible.reduction-fingerprint.v1\nfingerprint={}\nrepresentative={}\n",
        fingerprint.to_hex(),
        representative.to_hex()
    )
}

fn manifest_record_material(manifest: &CampaignManifest) -> String {
    format!(
        "format=crucible.campaign-manifest.v1\ncorpus_root={}\ncoverage_map_root={}\nfindings_root={}\ngenesis_pin={}\nprovenance.crucible_version={}\nprovenance.qemu_build={}\nprovenance.abi_versions={}\n",
        manifest.corpus_root.to_hex(),
        manifest.coverage_map_root.to_hex(),
        manifest.findings_root.to_hex(),
        manifest.genesis_pin.to_hex(),
        manifest.provenance.crucible_version,
        manifest.provenance.qemu_build,
        manifest.provenance.abi_versions,
    )
}

fn campaign_provenance_material(provenance: &CampaignProvenance) -> String {
    format!(
        "format={CAMPAIGN_PROVENANCE_SCHEMA}\ncrucible_version={}\nqemu_build={}\nabi_versions={}\n",
        provenance.crucible_version, provenance.qemu_build, provenance.abi_versions,
    )
}

fn campaign_lineage_material(manifest: &CampaignManifest, provenance_key: ContentHash) -> String {
    format!(
        "format={CAMPAIGN_LINEAGE_SCHEMA}\ngenesis_pin={}\nprovenance_key={provenance_key}\n",
        manifest.genesis_pin.to_hex(),
        provenance_key = provenance_key.to_hex(),
    )
}

fn campaign_fresh_lineage_baseline_event_material(
    event: &CampaignFreshLineageBaselineEvent,
) -> String {
    format!(
        "format={}\nreason={}\nrefused_corpus_root={}\nprevious_lineage_id={}\nfresh_lineage_id={}\nprevious_provenance_key={}\nrun_provenance_key={}\nfresh_manifest_hash={}\nfresh_manifest.corpus_root={}\nfresh_manifest.coverage_map_root={}\nfresh_manifest.findings_root={}\nfresh_manifest.genesis_pin={}\nfresh_manifest.provenance.crucible_version={}\nfresh_manifest.provenance.qemu_build={}\nfresh_manifest.provenance.abi_versions={}\n",
        event.schema_version,
        event.reason,
        event.refused_corpus_root.to_hex(),
        event.previous_lineage_id.to_hex(),
        event.fresh_lineage_id.to_hex(),
        event.previous_provenance_key.to_hex(),
        event.run_provenance_key.to_hex(),
        event.fresh_manifest_hash.to_hex(),
        event.fresh_manifest.corpus_root.to_hex(),
        event.fresh_manifest.coverage_map_root.to_hex(),
        event.fresh_manifest.findings_root.to_hex(),
        event.fresh_manifest.genesis_pin.to_hex(),
        event.fresh_manifest.provenance.crucible_version,
        event.fresh_manifest.provenance.qemu_build,
        event.fresh_manifest.provenance.abi_versions,
    )
}

fn campaign_replay_input_material(artifact: &CampaignReplayArtifact) -> String {
    format!(
        "format=crucible.campaign-replay-input.v1\ndefinition={}\nseed={}\nschedule={}\n",
        encode_hex(artifact.definition()),
        encode_hex(artifact.seed()),
        encode_hex(artifact.schedule())
    )
}

fn campaign_replay_artifact_material(artifact: &CampaignReplayArtifact) -> String {
    format!(
        "format=crucible.campaign-replay-artifact.v1\ndefinition={}\nseed={}\nschedule={}\nreplay_hash={}\n",
        encode_hex(artifact.definition()),
        encode_hex(artifact.seed()),
        encode_hex(artifact.schedule()),
        artifact.replay_hash().to_hex()
    )
}

fn campaign_corpus_record_material(entries: &BTreeMap<ContentHash, ContentHash>) -> String {
    let mut material = String::from("format=crucible.campaign-corpus.v1\n");
    for (artifact_hash, replay_hash) in entries {
        material.push_str(&format!(
            "entry artifact={} replay={}\n",
            artifact_hash.to_hex(),
            replay_hash.to_hex()
        ));
    }
    material
}

fn campaign_corpus_retention_record_material(
    source_root: ContentHash,
    policy: &CampaignCorpusRetentionPolicy,
    entries: &BTreeMap<ContentHash, ContentHash>,
) -> String {
    let mut material = format!(
        "format=crucible.campaign-corpus-retention.v1\nsource={}\ncap={}\nseed={}\n",
        source_root.to_hex(),
        policy.cap,
        policy.seed.to_hex()
    );
    for (artifact_hash, replay_hash) in entries {
        material.push_str(&format!(
            "entry artifact={} replay={}\n",
            artifact_hash.to_hex(),
            replay_hash.to_hex()
        ));
    }
    material
}

fn campaign_coverage_map_record_material(edges: &BTreeSet<ContentHash>) -> String {
    let mut material = String::from("format=crucible.campaign-coverage-map.v1\n");
    for edge in edges {
        material.push_str(&format!("edge={}\n", edge.to_hex()));
    }
    material
}

fn campaign_finding_record_material(
    finding: &CampaignFinding,
    artifact_hash: ContentHash,
) -> String {
    format!(
        "format=crucible.campaign-finding.v1\nfingerprint={}\nartifact={}\nreplay={}\n",
        finding.fingerprint.to_hex(),
        artifact_hash.to_hex(),
        finding.artifact.replay_hash().to_hex()
    )
}

fn campaign_findings_ledger_record_material(
    entries: &BTreeMap<ContentHash, ContentHash>,
) -> String {
    let mut material = String::from("format=crucible.campaign-findings-ledger.v1\n");
    for (artifact_hash, finding_hash) in entries {
        material.push_str(&format!(
            "entry artifact={} finding={}\n",
            artifact_hash.to_hex(),
            finding_hash.to_hex()
        ));
    }
    material
}

fn campaign_head_entry_material(generation: u64, manifest_hash: ContentHash) -> String {
    let checksum = campaign_head_entry_checksum(generation, manifest_hash);
    format!(
        "entry generation={generation} manifest={} checksum={}\n",
        manifest_hash.to_hex(),
        checksum.to_hex()
    )
}

fn campaign_head_entry_checksum(generation: u64, manifest_hash: ContentHash) -> ContentHash {
    ContentHash::from_bytes(
        format!(
            "crucible.campaign-head-entry.v1\ngeneration={generation}\nmanifest={}\n",
            manifest_hash.to_hex()
        )
        .as_bytes(),
    )
}

fn frontier_lease_id(node: &ContentHash, owner: &str, expires_at_tick: u64) -> ContentHash {
    ContentHash::from_bytes(
        format!(
            "crucible.frontier-lease.v1\nnode={}\nowner={owner}\nexpires_at_tick={expires_at_tick}\n",
            node.to_hex()
        )
        .as_bytes(),
    )
}

fn lease_record_material(lease: &FrontierLease) -> String {
    format!(
        "format=crucible.frontier-lease.v1\nnode={}\nowner={}\nexpires_at_tick={}\nlease_id={}\n",
        lease.node.to_hex(),
        lease.owner,
        lease.expires_at_tick,
        lease.lease_id.to_hex()
    )
}

fn claim_lock_record_material(
    node: &ContentHash,
    acquired_at_tick: u64,
    expires_at_tick: u64,
) -> String {
    format!(
        "format=crucible.frontier-claim-lock.v1\nnode={}\nacquired_at_tick={acquired_at_tick}\nexpires_at_tick={expires_at_tick}\n",
        node.to_hex()
    )
}

fn parse_lease_record(
    path: &Path,
    expected_node: &ContentHash,
    material: &str,
) -> Result<FrontierLease, CasError> {
    let mut fields = BTreeMap::new();
    for line in material.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(CasError::InvalidFrontierRecord {
                path: path.to_path_buf(),
                reason: "claim record line is missing '='",
            });
        };
        fields.insert(key, value);
    }
    if fields.get("format") != Some(&"crucible.frontier-lease.v1") {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record format is unsupported",
        });
    }
    let node = parse_required_hash(path, &fields, "node")?;
    if node != *expected_node {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record node does not match claim path",
        });
    }
    let owner = fields
        .get("owner")
        .ok_or_else(|| CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record is missing owner",
        })?
        .to_string();
    let expires_at_tick = fields
        .get("expires_at_tick")
        .ok_or_else(|| CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record is missing expiry",
        })?
        .parse::<u64>()
        .map_err(|_| CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record expiry is not a u64",
        })?;
    let lease_id = parse_required_hash(path, &fields, "lease_id")?;
    let expected_lease_id = frontier_lease_id(&node, &owner, expires_at_tick);
    if lease_id != expected_lease_id {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record lease id does not match record material",
        });
    }
    Ok(FrontierLease {
        node,
        owner,
        expires_at_tick,
        lease_id,
    })
}

fn parse_reduction_record(
    path: &Path,
    expected_fingerprint: &ContentHash,
    material: &str,
) -> Result<ContentHash, CasError> {
    let mut fields = BTreeMap::new();
    for line in material.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(CasError::InvalidFrontierRecord {
                path: path.to_path_buf(),
                reason: "reduction record line is missing '='",
            });
        };
        fields.insert(key, value);
    }
    if fields.get("format") != Some(&"crucible.reduction-fingerprint.v1") {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "reduction record format is unsupported",
        });
    }
    let fingerprint = parse_required_hash(path, &fields, "fingerprint")?;
    if fingerprint != *expected_fingerprint {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "reduction record fingerprint does not match marker path",
        });
    }
    parse_required_hash(path, &fields, "representative")
}

fn parse_manifest_record(path: &Path, material: &str) -> Result<CampaignManifest, CasError> {
    let fields = parse_key_value_record(path, material, "campaign manifest")?;
    if fields.get("format") != Some(&"crucible.campaign-manifest.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign manifest format is unsupported",
        });
    }
    let manifest = CampaignManifest {
        corpus_root: parse_required_campaign_hash(path, &fields, "corpus_root")?,
        coverage_map_root: parse_required_campaign_hash(path, &fields, "coverage_map_root")?,
        findings_root: parse_required_campaign_hash(path, &fields, "findings_root")?,
        genesis_pin: parse_required_campaign_hash(path, &fields, "genesis_pin")?,
        provenance: CampaignProvenance {
            crucible_version: parse_required_string(path, &fields, "provenance.crucible_version")?,
            qemu_build: parse_required_string(path, &fields, "provenance.qemu_build")?,
            abi_versions: parse_required_string(path, &fields, "provenance.abi_versions")?,
        },
    };
    validate_campaign_manifest(&manifest)?;
    Ok(manifest)
}

fn parse_replay_artifact_record(
    path: &Path,
    material: &str,
) -> Result<CampaignReplayArtifact, CasError> {
    let fields = parse_key_value_record(path, material, "campaign replay artifact")?;
    if fields.get("format") != Some(&"crucible.campaign-replay-artifact.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign replay artifact format is unsupported",
        });
    }
    let artifact = CampaignReplayArtifact::new(
        decode_hex_field(path, &fields, "definition")?,
        decode_hex_field(path, &fields, "seed")?,
        decode_hex_field(path, &fields, "schedule")?,
    );
    let replay_hash = parse_required_campaign_hash(path, &fields, "replay_hash")?;
    if replay_hash != artifact.replay_hash() {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign replay artifact hash is invalid",
        });
    }
    Ok(artifact)
}

fn parse_campaign_corpus_record(
    path: &Path,
    material: &str,
) -> Result<BTreeMap<ContentHash, ContentHash>, CasError> {
    let mut lines = material.lines();
    if lines.next() != Some("format=crucible.campaign-corpus.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus format is unsupported",
        });
    }
    let mut entries = BTreeMap::new();
    for line in lines {
        let Some(fields_material) = line.strip_prefix("entry ") else {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign corpus entry line is unsupported",
            });
        };
        let fields = parse_space_fields(path, fields_material, "campaign corpus entry")?;
        let artifact = parse_required_campaign_hash(path, &fields, "artifact")?;
        let replay = parse_required_campaign_hash(path, &fields, "replay")?;
        entries.insert(artifact, replay);
    }
    Ok(entries)
}

fn parse_campaign_corpus_retention_record(
    path: &Path,
    material: &str,
) -> Result<CampaignCorpusRetentionRecord, CasError> {
    let mut lines = material.lines();
    if lines.next() != Some("format=crucible.campaign-corpus-retention.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention format is unsupported",
        });
    }
    let source_line = lines
        .next()
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention source is missing",
        })?;
    let Some(source_hex) = source_line.strip_prefix("source=") else {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention source is missing",
        });
    };
    let source_root =
        ContentHash::from_hex(source_hex).ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention source hash is invalid",
        })?;

    let cap_line = lines
        .next()
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention cap is missing",
        })?;
    let Some(cap_value) = cap_line.strip_prefix("cap=") else {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention cap is missing",
        });
    };
    let cap = cap_value
        .parse::<usize>()
        .map_err(|_| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention cap is invalid",
        })?;
    if cap == 0 {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention cap must be greater than zero",
        });
    }

    let seed_line = lines
        .next()
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention seed is missing",
        })?;
    let Some(seed_hex) = seed_line.strip_prefix("seed=") else {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign corpus retention seed is missing",
        });
    };
    let seed = ContentHash::from_hex(seed_hex).ok_or_else(|| CasError::InvalidCampaignRecord {
        path: path.to_path_buf(),
        reason: "campaign corpus retention seed hash is invalid",
    })?;

    let mut entries = BTreeMap::new();
    for line in lines {
        let Some(fields_material) = line.strip_prefix("entry ") else {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign corpus retention entry line is unsupported",
            });
        };
        let fields = parse_space_fields(path, fields_material, "campaign corpus entry")?;
        let artifact = parse_required_campaign_hash(path, &fields, "artifact")?;
        let replay = parse_required_campaign_hash(path, &fields, "replay")?;
        entries.insert(artifact, replay);
    }

    Ok(CampaignCorpusRetentionRecord {
        source_root,
        policy: CampaignCorpusRetentionPolicy { cap, seed },
        entries,
    })
}

fn parse_campaign_coverage_map_record(
    path: &Path,
    material: &str,
) -> Result<BTreeSet<ContentHash>, CasError> {
    let mut lines = material.lines();
    if lines.next() != Some("format=crucible.campaign-coverage-map.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign coverage-map format is unsupported",
        });
    }
    let mut edges = BTreeSet::new();
    for line in lines {
        let Some(edge) = line.strip_prefix("edge=") else {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign coverage-map edge line is unsupported",
            });
        };
        edges.insert(ContentHash::from_hex(edge).ok_or_else(|| {
            CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign coverage-map edge hash is invalid",
            }
        })?);
    }
    Ok(edges)
}

fn parse_campaign_finding_record(
    path: &Path,
    finding_hash: ContentHash,
    material: &str,
) -> Result<PersistedCampaignFinding, CasError> {
    let fields = parse_key_value_record(path, material, "campaign finding")?;
    if fields.get("format") != Some(&"crucible.campaign-finding.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign finding format is unsupported",
        });
    }
    Ok(PersistedCampaignFinding {
        finding_hash,
        fingerprint: parse_required_campaign_hash(path, &fields, "fingerprint")?,
        artifact_hash: parse_required_campaign_hash(path, &fields, "artifact")?,
        replay_hash: parse_required_campaign_hash(path, &fields, "replay")?,
    })
}

fn parse_campaign_findings_ledger_record(
    path: &Path,
    material: &str,
) -> Result<BTreeMap<ContentHash, ContentHash>, CasError> {
    let mut lines = material.lines();
    if lines.next() != Some("format=crucible.campaign-findings-ledger.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign findings ledger format is unsupported",
        });
    }
    let mut findings = BTreeMap::new();
    for line in lines {
        let Some(fields_material) = line.strip_prefix("entry ") else {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign findings ledger line is unsupported",
            });
        };
        let fields = parse_space_fields(path, fields_material, "campaign findings ledger entry")?;
        let artifact = parse_required_campaign_hash(path, &fields, "artifact")?;
        let finding = parse_required_campaign_hash(path, &fields, "finding")?;
        insert_deduped_finding_entry(&mut findings, artifact, finding);
    }
    Ok(findings)
}

fn parse_campaign_root_merge_record(
    path: &Path,
    material: &str,
) -> Result<CampaignRootMerge, CasError> {
    let fields = parse_key_value_record(path, material, "campaign root merge")?;
    if fields.get("format") != Some(&"crucible.campaign-root-merge.v1") {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign root merge format is unsupported",
        });
    }
    let label = match fields.get("label").copied() {
        Some("corpus") => "corpus",
        Some("coverage-map") => "coverage-map",
        Some("findings") => "findings",
        Some(_) => {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign root merge label is unsupported",
            });
        }
        None => {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign root merge is missing label",
            });
        }
    };
    Ok(CampaignRootMerge {
        label,
        left: parse_required_campaign_hash(path, &fields, "left")?,
        right: parse_required_campaign_hash(path, &fields, "right")?,
    })
}

fn parse_fresh_lineage_baseline_event(
    path: &Path,
    baseline_event_hash: ContentHash,
    material: &str,
) -> Result<CampaignFreshLineageBaselineEvent, CasError> {
    let fields = parse_key_value_record(path, material, "fresh-lineage baseline event")?;
    if fields.get("format") != Some(&CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA) {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "fresh-lineage baseline event format is unsupported",
        });
    }
    let fresh_manifest = CampaignManifest {
        corpus_root: parse_required_campaign_hash(path, &fields, "fresh_manifest.corpus_root")?,
        coverage_map_root: parse_required_campaign_hash(
            path,
            &fields,
            "fresh_manifest.coverage_map_root",
        )?,
        findings_root: parse_required_campaign_hash(path, &fields, "fresh_manifest.findings_root")?,
        genesis_pin: parse_required_campaign_hash(path, &fields, "fresh_manifest.genesis_pin")?,
        provenance: CampaignProvenance {
            crucible_version: parse_required_string(
                path,
                &fields,
                "fresh_manifest.provenance.crucible_version",
            )?,
            qemu_build: parse_required_string(
                path,
                &fields,
                "fresh_manifest.provenance.qemu_build",
            )?,
            abi_versions: parse_required_string(
                path,
                &fields,
                "fresh_manifest.provenance.abi_versions",
            )?,
        },
    };
    validate_campaign_manifest(&fresh_manifest)?;
    let event = CampaignFreshLineageBaselineEvent {
        baseline_event_hash,
        schema_version: CAMPAIGN_FRESH_LINEAGE_BASELINE_EVENT_SCHEMA.to_owned(),
        reason: parse_required_string(path, &fields, "reason")?,
        refused_corpus_root: parse_required_campaign_hash(path, &fields, "refused_corpus_root")?,
        previous_lineage_id: parse_required_campaign_hash(path, &fields, "previous_lineage_id")?,
        fresh_lineage_id: parse_required_campaign_hash(path, &fields, "fresh_lineage_id")?,
        previous_provenance_key: parse_required_campaign_hash(
            path,
            &fields,
            "previous_provenance_key",
        )?,
        run_provenance_key: parse_required_campaign_hash(path, &fields, "run_provenance_key")?,
        fresh_manifest_hash: parse_required_campaign_hash(path, &fields, "fresh_manifest_hash")?,
        fresh_manifest,
    };
    if event.reason != CAMPAIGN_CROSS_PROVENANCE_REFUSAL_REASON {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "fresh-lineage baseline event reason is unsupported",
        });
    }
    if event.fresh_lineage_id != campaign_lineage_id(&event.fresh_manifest)? {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "fresh-lineage baseline event lineage id is invalid",
        });
    }
    if event.run_provenance_key != campaign_provenance_key(&event.fresh_manifest.provenance)? {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "fresh-lineage baseline event provenance key is invalid",
        });
    }
    Ok(event)
}

fn parse_campaign_head_record(
    path: &Path,
    material: &str,
) -> Result<Option<CampaignHeadPointer>, CasError> {
    parse_campaign_head_log_record(path, material)
}

fn parse_campaign_head_log_record(
    path: &Path,
    material: &str,
) -> Result<Option<CampaignHeadPointer>, CasError> {
    let mut latest = None;
    for line in material.lines() {
        match parse_campaign_head_entry(path, line) {
            Ok(pointer) => {
                if latest
                    .map(|current: CampaignHeadPointer| pointer.generation > current.generation)
                    .unwrap_or(true)
                {
                    latest = Some(pointer);
                }
            }
            Err(error) if line.starts_with("entry ") => {
                let _ = error;
            }
            Err(error) => {
                let _ = error;
            }
        }
    }
    Ok(latest)
}

fn parse_campaign_head_entry(path: &Path, line: &str) -> Result<CampaignHeadPointer, CasError> {
    let Some(fields_material) = line.strip_prefix("entry ") else {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign head log line is unsupported",
        });
    };
    let mut fields = BTreeMap::new();
    for field in fields_material.split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason: "campaign head entry field is missing '='",
            });
        };
        fields.insert(key, value);
    }
    let generation = fields
        .get("generation")
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign head entry is missing generation",
        })?
        .parse::<u64>()
        .map_err(|_| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign head entry generation is invalid",
        })?;
    let manifest_hash = parse_required_campaign_hash(path, &fields, "manifest")?;
    let checksum = parse_required_campaign_hash(path, &fields, "checksum")?;
    if checksum != campaign_head_entry_checksum(generation, manifest_hash) {
        return Err(CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign head entry checksum is invalid",
        });
    }
    Ok(CampaignHeadPointer {
        generation,
        manifest_hash,
    })
}

fn parse_claim_lock_record(
    path: &Path,
    expected_node: &ContentHash,
    material: &str,
) -> Result<FrontierClaimLockRecord, CasError> {
    let mut fields = BTreeMap::new();
    for line in material.lines() {
        let Some((key, value)) = line.split_once('=') else {
            return Err(CasError::InvalidFrontierRecord {
                path: path.to_path_buf(),
                reason: "claim lock record line is missing '='",
            });
        };
        fields.insert(key, value);
    }
    if fields.get("format") != Some(&"crucible.frontier-claim-lock.v1") {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim lock record format is unsupported",
        });
    }
    let node = parse_required_hash(path, &fields, "node")?;
    if node != *expected_node {
        return Err(CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim lock node does not match lock path",
        });
    }
    let expires_at_tick = fields
        .get("expires_at_tick")
        .ok_or_else(|| CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim lock record is missing expiry",
        })?
        .parse::<u64>()
        .map_err(|_| CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim lock record expiry is not a u64",
        })?;
    Ok(FrontierClaimLockRecord {
        node,
        expires_at_tick,
    })
}

fn parse_key_value_record<'a>(
    path: &Path,
    material: &'a str,
    label: &'static str,
) -> Result<BTreeMap<&'a str, &'a str>, CasError> {
    let mut fields = BTreeMap::new();
    for line in material.lines() {
        let Some((key, value)) = line.split_once('=') else {
            let reason = match label {
                "campaign manifest" => "campaign manifest line is missing '='",
                "campaign head" => "campaign head line is missing '='",
                _ => "record line is missing '='",
            };
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason,
            });
        };
        fields.insert(key, value);
    }
    Ok(fields)
}

fn parse_space_fields<'a>(
    path: &Path,
    material: &'a str,
    label: &'static str,
) -> Result<BTreeMap<&'a str, &'a str>, CasError> {
    let mut fields = BTreeMap::new();
    for field in material.split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            let reason = match label {
                "campaign corpus entry" => "campaign corpus entry field is missing '='",
                _ => "record field is missing '='",
            };
            return Err(CasError::InvalidCampaignRecord {
                path: path.to_path_buf(),
                reason,
            });
        };
        fields.insert(key, value);
    }
    Ok(fields)
}

fn parse_required_hash(
    path: &Path,
    fields: &BTreeMap<&str, &str>,
    name: &'static str,
) -> Result<ContentHash, CasError> {
    let value = fields
        .get(name)
        .ok_or_else(|| CasError::InvalidFrontierRecord {
            path: path.to_path_buf(),
            reason: "claim record is missing hash field",
        })?;
    ContentHash::from_hex(value).ok_or_else(|| CasError::InvalidFrontierRecord {
        path: path.to_path_buf(),
        reason: "claim record hash field is invalid",
    })
}

fn parse_required_string(
    path: &Path,
    fields: &BTreeMap<&str, &str>,
    name: &'static str,
) -> Result<String, CasError> {
    let value = fields
        .get(name)
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign record is missing string field",
        })?;
    Ok((*value).to_string())
}

fn parse_required_campaign_hash(
    path: &Path,
    fields: &BTreeMap<&str, &str>,
    name: &'static str,
) -> Result<ContentHash, CasError> {
    let value = fields
        .get(name)
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign record is missing hash field",
        })?;
    ContentHash::from_hex(value).ok_or_else(|| CasError::InvalidCampaignRecord {
        path: path.to_path_buf(),
        reason: "campaign record hash field is invalid",
    })
}

fn decode_hex_field(
    path: &Path,
    fields: &BTreeMap<&str, &str>,
    name: &'static str,
) -> Result<Vec<u8>, CasError> {
    let value = fields
        .get(name)
        .ok_or_else(|| CasError::InvalidCampaignRecord {
            path: path.to_path_buf(),
            reason: "campaign record is missing bytes field",
        })?;
    decode_hex(value).ok_or_else(|| CasError::InvalidCampaignRecord {
        path: path.to_path_buf(),
        reason: "campaign record bytes field is invalid",
    })
}

fn validate_campaign_manifest(manifest: &CampaignManifest) -> Result<(), CasError> {
    validate_campaign_provenance(&manifest.provenance)?;
    Ok(())
}

fn validate_campaign_provenance(provenance: &CampaignProvenance) -> Result<(), CasError> {
    validate_campaign_provenance_field(&provenance.crucible_version)?;
    validate_campaign_provenance_field(&provenance.qemu_build)?;
    validate_campaign_provenance_field(&provenance.abi_versions)?;
    Ok(())
}

fn validate_campaign_provenance_field(value: &str) -> Result<(), CasError> {
    if value.is_empty() {
        return Err(CasError::InvalidCampaignRecord {
            path: PathBuf::from("campaign-manifest"),
            reason: "campaign provenance field must not be empty",
        });
    }
    if value.contains('\n') {
        return Err(CasError::InvalidCampaignRecord {
            path: PathBuf::from("campaign-manifest"),
            reason: "campaign provenance field must not contain newlines",
        });
    }
    Ok(())
}

fn validate_campaign_lineage(
    current: &CampaignManifest,
    proposed: &CampaignManifest,
) -> Result<(), CasError> {
    if current.genesis_pin != proposed.genesis_pin {
        return Err(CasError::InvalidCampaignRecord {
            path: PathBuf::from("campaign-manifest"),
            reason: "campaign manifests with different genesis pins cannot merge",
        });
    }
    if current.provenance != proposed.provenance {
        return Err(CasError::InvalidCampaignRecord {
            path: PathBuf::from("campaign-manifest"),
            reason: "campaign manifests with different provenance cannot merge",
        });
    }
    Ok(())
}

fn validate_campaign_corpus_retention_policy(
    policy: &CampaignCorpusRetentionPolicy,
    path: PathBuf,
) -> Result<(), CasError> {
    if policy.cap == 0 {
        return Err(CasError::InvalidCampaignRecord {
            path,
            reason: "campaign corpus retention cap must be greater than zero",
        });
    }
    Ok(())
}

fn campaign_root_field(label: &str) -> &'static str {
    match label {
        "corpus" => "corpus_root",
        "coverage-map" => "coverage_map_root",
        "findings" => "findings_root",
        _ => "manifest_root",
    }
}

fn campaign_root_regression_reason(label: &str) -> &'static str {
    match label {
        "corpus" => "typed campaign corpus root cannot be replaced by an untyped root",
        "coverage-map" => "typed campaign coverage-map root cannot be replaced by an untyped root",
        "findings" => "typed campaign findings root cannot be replaced by an untyped root",
        _ => "typed campaign root cannot be replaced by an untyped root",
    }
}

fn is_typed_campaign_root_format(label: &str, format: &str) -> bool {
    match label {
        "corpus" => {
            matches!(
                format,
                "crucible.campaign-corpus.v1" | "crucible.campaign-corpus-retention.v1"
            )
        }
        "coverage-map" => format == "crucible.campaign-coverage-map.v1",
        "findings" => format == "crucible.campaign-findings-ledger.v1",
        _ => false,
    }
}

fn record_format(material: &str) -> Option<&str> {
    material.lines().next()?.strip_prefix("format=")
}

fn retain_campaign_corpus_entries(
    entries: &BTreeMap<ContentHash, ContentHash>,
    policy: &CampaignCorpusRetentionPolicy,
) -> BTreeMap<ContentHash, ContentHash> {
    let mut scored_entries = entries
        .iter()
        .map(|(artifact_hash, replay_hash)| {
            (
                campaign_corpus_retention_score(policy.seed, *artifact_hash, *replay_hash),
                *artifact_hash,
                *replay_hash,
            )
        })
        .collect::<Vec<_>>();
    scored_entries.sort();
    scored_entries
        .into_iter()
        .take(policy.cap)
        .map(|(_, artifact_hash, replay_hash)| (artifact_hash, replay_hash))
        .collect()
}

fn campaign_corpus_retention_score(
    seed: ContentHash,
    artifact_hash: ContentHash,
    replay_hash: ContentHash,
) -> ContentHash {
    ContentHash::from_bytes(
        format!(
            "crucible.campaign-corpus-retention-score.v1\nseed={}\nartifact={}\nreplay={}\n",
            seed.to_hex(),
            artifact_hash.to_hex(),
            replay_hash.to_hex()
        )
        .as_bytes(),
    )
}

fn campaign_root_merge_hash(label: &str, left: ContentHash, right: ContentHash) -> ContentHash {
    if left == right {
        return left;
    }
    let (first, second) = ordered_manifest_roots(left, right);
    ContentHash::from_bytes(campaign_root_merge_record_material(label, first, second).as_bytes())
}

fn campaign_root_merge_record_material(
    label: &str,
    first: ContentHash,
    second: ContentHash,
) -> String {
    format!(
        "format=crucible.campaign-root-merge.v1\nlabel={label}\nleft={}\nright={}\n",
        first.to_hex(),
        second.to_hex()
    )
}

fn ordered_manifest_roots(left: ContentHash, right: ContentHash) -> (ContentHash, ContentHash) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

fn insert_deduped_finding_entry(
    entries: &mut BTreeMap<ContentHash, ContentHash>,
    artifact_hash: ContentHash,
    finding_hash: ContentHash,
) {
    match entries.entry(artifact_hash) {
        Entry::Vacant(entry) => {
            entry.insert(finding_hash);
        }
        Entry::Occupied(mut entry) if finding_hash < *entry.get() => {
            entry.insert(finding_hash);
        }
        Entry::Occupied(_) => {}
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let mut decoded = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

static FRONTIER_CLAIM_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn frontier_claim_temp_path(path: &Path, lease: &FrontierLease) -> PathBuf {
    let mut temp_path = path.to_path_buf();
    let sequence = FRONTIER_CLAIM_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    temp_path.set_file_name(format!(
        ".{}.{}.{}.claim.tmp",
        lease.lease_id.to_hex(),
        std::process::id(),
        sequence
    ));
    temp_path
}

fn frontier_claim_lock_temp_path(path: &Path, node: &ContentHash, expires_at_tick: u64) -> PathBuf {
    let mut temp_path = path.to_path_buf();
    let sequence = FRONTIER_CLAIM_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    temp_path.set_file_name(format!(
        ".{}.{}.{}.{}.claim-lock.tmp",
        node.to_hex(),
        expires_at_tick,
        std::process::id(),
        sequence
    ));
    temp_path
}

/// A named set of content-addressed inputs recorded for an invalidation query.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DependencySnapshot {
    inputs: BTreeMap<String, ContentHash>,
}

impl DependencySnapshot {
    /// Builds an empty dependency snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `hash` for dependency `name`.
    pub fn insert(&mut self, name: impl Into<String>, hash: ContentHash) {
        self.inputs.insert(name.into(), hash);
    }

    /// Returns the recorded hash for `name`, if present.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<ContentHash> {
        self.inputs.get(name).copied()
    }

    /// Returns an iterator over dependency names and content hashes.
    pub fn iter(&self) -> impl Iterator<Item = (&str, ContentHash)> {
        self.inputs
            .iter()
            .map(|(name, hash)| (name.as_str(), *hash))
    }

    /// Returns the number of dependencies in the snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Returns whether the snapshot contains no dependencies.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }
}

/// A dependency-gated invalidation query for a previously computed node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidationQuery {
    baseline: DependencySnapshot,
}

impl InvalidationQuery {
    /// Builds a query from the dependency snapshot recorded with a node.
    #[must_use]
    pub fn new(baseline: DependencySnapshot) -> Self {
        Self { baseline }
    }

    /// Returns the baseline dependency snapshot.
    #[must_use]
    pub fn baseline(&self) -> &DependencySnapshot {
        &self.baseline
    }

    /// Evaluates the query against `current` dependency hashes.
    #[must_use]
    pub fn evaluate(&self, current: &DependencySnapshot) -> InvalidationDecision {
        let mut names = BTreeSet::new();
        for (name, _) in self.baseline.iter() {
            names.insert(name.to_owned());
        }
        for (name, _) in current.iter() {
            names.insert(name.to_owned());
        }

        let mut changed = BTreeMap::new();
        for name in names {
            let before = self.baseline.get(&name);
            let after = current.get(&name);
            if before != after {
                changed.insert(name, DependencyChange { before, after });
            }
        }

        InvalidationDecision { changed }
    }

    /// Returns whether `current` invalidates the node.
    #[must_use]
    pub fn is_invalid(&self, current: &DependencySnapshot) -> bool {
        self.evaluate(current).is_invalid()
    }
}

/// The result of a dependency-gated invalidation query.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InvalidationDecision {
    changed: BTreeMap<String, DependencyChange>,
}

impl InvalidationDecision {
    /// Returns whether any dependency hash changed, appeared, or disappeared.
    #[must_use]
    pub fn is_invalid(&self) -> bool {
        !self.changed.is_empty()
    }

    /// Returns the inputs whose hashes changed.
    #[must_use]
    pub fn changed_inputs(&self) -> &BTreeMap<String, DependencyChange> {
        &self.changed
    }
}

/// A before/after dependency hash pair for one changed input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DependencyChange {
    /// The hash recorded with the node, if the dependency existed then.
    pub before: Option<ContentHash>,
    /// The hash observed for the dependency now, if the dependency exists now.
    pub after: Option<ContentHash>,
}

fn local_store_temp_path(path: &Path, key: &ContentHash) -> PathBuf {
    let mut temp_path = path.to_path_buf();
    temp_path.set_file_name(format!(".{}.tmp", key.to_hex()));
    temp_path
}

static SHARED_STORE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
const SHARED_STORE_TEMP_CREATE_ATTEMPTS: usize = 4096;

fn shared_store_temp_path(path: &Path, key: &ContentHash, sequence: u64) -> PathBuf {
    let mut temp_path = path.to_path_buf();
    temp_path.set_file_name(format!(
        ".{}.{}.{}.tmp",
        key.to_hex(),
        std::process::id(),
        sequence
    ));
    temp_path
}

fn create_shared_store_temp_file(
    path: &Path,
    key: &ContentHash,
    bytes: &[u8],
) -> Result<PathBuf, CasError> {
    create_shared_store_temp_file_with(path, key, bytes, || {
        SHARED_STORE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    })
}

fn create_shared_store_temp_file_with(
    path: &Path,
    key: &ContentHash,
    bytes: &[u8],
    mut next_sequence: impl FnMut() -> u64,
) -> Result<PathBuf, CasError> {
    for _ in 0..SHARED_STORE_TEMP_CREATE_ATTEMPTS {
        let temp_path = shared_store_temp_path(path, key, next_sequence());
        let mut temp_file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(temp_file) => temp_file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => {
                return Err(CasError::Io {
                    operation: "create-temp",
                    path: temp_path,
                    source,
                });
            }
        };
        if let Err(source) = temp_file.write_all(bytes) {
            let _ = fs::remove_file(&temp_path);
            return Err(CasError::Io {
                operation: "write",
                path: temp_path,
                source,
            });
        }
        return Ok(temp_path);
    }

    Err(CasError::Io {
        operation: "create-temp",
        path: path.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "exhausted shared store temporary path attempts",
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn memory_store_deduplicates_identical_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let store = MemoryDagStore::new();

        let first = store.put(b"checkpoint")?;
        let second = store.put(b"checkpoint")?;

        assert_eq!(first, second);
        assert_eq!(store.object_count()?, 1);
        assert!(store.has(&first)?);
        assert_eq!(store.get(&first)?, b"checkpoint");

        Ok(())
    }

    #[test]
    fn local_store_uses_two_level_layout_and_validates_content()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = LocalDagStore::new(temp.path());
        let key = store.put(b"node")?;
        let path = store.object_path(&key);
        let hex = key.to_hex();

        assert_eq!(path, temp.path().join(&hex[0..2]).join(&hex));
        assert!(store.has(&key)?);
        assert_eq!(store.get(&key)?, b"node");

        fs::write(&path, b"corrupt")?;
        assert!(matches!(
            store.get(&key),
            Err(CasError::ContentMismatch { expected, .. }) if expected == key
        ));

        Ok(())
    }

    #[test]
    fn shared_store_identity_is_location_independent() -> Result<(), Box<dyn std::error::Error>> {
        let left_temp = tempfile::tempdir()?;
        let right_temp = tempfile::tempdir()?;
        let left = SharedDagStore::new(left_temp.path());
        let right = SharedDagStore::new(right_temp.path());

        let left_key = left.put(b"fleet-checkpoint")?;
        let right_key = right.put(b"fleet-checkpoint")?;

        assert_eq!(left_key, right_key);
        assert_eq!(left.get(&left_key)?, right.get(&right_key)?);
        assert_ne!(left.object_path(&left_key), right.object_path(&right_key));
        assert_eq!(
            left.object_path(&left_key).file_name(),
            right.object_path(&right_key).file_name()
        );

        Ok(())
    }

    #[test]
    fn shared_store_concurrent_put_is_idempotent() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = Arc::new(SharedDagStore::new(temp.path()));
        let mut handles = Vec::new();

        for _ in 0..16 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || store.put(b"shared-frontier-node")));
        }

        let mut keys = BTreeSet::new();
        for handle in handles {
            keys.insert(
                handle
                    .join()
                    .map_err(|_| std::io::Error::other("shared store writer panicked"))??,
            );
        }

        assert_eq!(keys.len(), 1);
        let key = keys
            .iter()
            .next()
            .copied()
            .ok_or_else(|| std::io::Error::other("shared store did not publish a key"))?;
        assert!(store.has(&key)?);
        assert_eq!(store.get(&key)?, b"shared-frontier-node");

        Ok(())
    }

    #[test]
    fn shared_store_temp_creation_skips_existing_collision()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SharedDagStore::new(temp.path());
        let key = ContentHash::from_bytes(b"shared-temp-collision");
        let path = store.object_path(&key);
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("shared store object path has no parent"))?;
        fs::create_dir_all(parent)?;

        let stale_temp = shared_store_temp_path(&path, &key, 0);
        fs::write(&stale_temp, b"stale writer temp")?;
        let mut sequences = [0_u64, 1].into_iter();

        let created =
            create_shared_store_temp_file_with(&path, &key, b"shared-temp-collision", || {
                sequences.next().unwrap_or(2)
            })?;

        assert_ne!(created, stale_temp);
        assert_eq!(fs::read(&stale_temp)?, b"stale writer temp");
        assert_eq!(fs::read(&created)?, b"shared-temp-collision");

        Ok(())
    }

    #[test]
    fn shared_frontier_claims_expired_leases_again() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SharedDagStore::new(temp.path().join("objects"));
        let frontier = SharedFrontier::new(temp.path().join("frontier"));
        let node = store.put(b"frontier-node")?;
        frontier.admit(&node)?;

        let first = frontier
            .claim_next(&FrontierClaimRequest::new("host-a", 10, 5))?
            .ok_or_else(|| std::io::Error::other("first claim did not lease a node"))?;
        assert_eq!(first.node, node);
        assert_eq!(first.owner, "host-a");
        assert_eq!(first.expires_at_tick, 15);
        assert!(
            frontier
                .claim_next(&FrontierClaimRequest::new("host-b", 11, 5))?
                .is_none()
        );

        let reclaimed = frontier
            .claim_next(&FrontierClaimRequest::new("host-b", 15, 5))?
            .ok_or_else(|| std::io::Error::other("expired claim did not become claimable"))?;
        assert_eq!(reclaimed.node, node);
        assert_eq!(reclaimed.owner, "host-b");
        assert_ne!(reclaimed.lease_id, first.lease_id);
        assert_eq!(store.put(b"frontier-node")?, node);
        assert_eq!(store.get(&node)?, b"frontier-node");

        let claim_path = frontier.claim_path(&node);
        let claim_file = claim_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| std::io::Error::other("claim path has no UTF-8 file name"))?;
        assert_eq!(claim_file, node.to_hex());
        assert!(!claim_path.to_string_lossy().contains("host-a"));
        assert!(!claim_path.to_string_lossy().contains("host-b"));

        Ok(())
    }

    #[test]
    fn shared_frontier_claim_is_single_owner_under_contention()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SharedDagStore::new(temp.path().join("objects"));
        let frontier = Arc::new(SharedFrontier::new(temp.path().join("frontier")));
        let node = store.put(b"contended-frontier-node")?;
        frontier.admit(&node)?;
        let workers = 16;
        let barrier = Arc::new(Barrier::new(workers));
        let mut handles = Vec::new();

        for worker in 0..workers {
            let frontier = Arc::clone(&frontier);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                frontier.claim_next(&FrontierClaimRequest::new(format!("host-{worker}"), 100, 5))
            }));
        }

        let mut leases = Vec::new();
        for handle in handles {
            if let Some(lease) = handle
                .join()
                .map_err(|_| std::io::Error::other("frontier claimant panicked"))??
            {
                leases.push(lease);
            }
        }

        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].node, node);
        assert!(
            frontier
                .claim_next(&FrontierClaimRequest::new("late-host", 101, 5))?
                .is_none()
        );

        Ok(())
    }

    #[test]
    fn shared_frontier_reclaims_expired_claim_lock() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SharedDagStore::new(temp.path().join("objects"));
        let frontier = SharedFrontier::new(temp.path().join("frontier"));
        let node = store.put(b"stale-lock-frontier-node")?;
        frontier.admit(&node)?;
        let lock_path = frontier.claim_lock_path(&node);
        let parent = lock_path
            .parent()
            .ok_or_else(|| std::io::Error::other("claim lock path has no parent"))?;
        fs::create_dir_all(parent)?;
        fs::write(&lock_path, claim_lock_record_material(&node, 100, 105))?;

        assert!(
            frontier
                .claim_next(&FrontierClaimRequest::new("blocked-host", 104, 5))?
                .is_none()
        );
        let reclaimed = frontier
            .claim_next(&FrontierClaimRequest::new("reclaiming-host", 105, 5))?
            .ok_or_else(|| std::io::Error::other("expired claim lock was not reclaimed"))?;

        assert_eq!(reclaimed.node, node);
        assert_eq!(reclaimed.owner, "reclaiming-host");
        assert_eq!(reclaimed.expires_at_tick, 110);

        Ok(())
    }

    #[test]
    fn shared_dedup_index_proves_four_layers() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SharedDagStore::new(temp.path().join("objects"));
        let index = SharedDedupIndex::new(temp.path().join("dedup"));
        let child = ContentHash::from_bytes(b"four-layer-child");

        assert_eq!(
            index.exists_gated_expansion(&store, &child)?,
            ExpansionDedupDecision::Expand
        );
        assert_eq!(store.put(b"four-layer-child")?, child);
        assert_eq!(
            index.exists_gated_expansion(&store, &child)?,
            ExpansionDedupDecision::SkipExisting
        );

        let edge_a = ContentHash::from_bytes(b"coverage-edge-a");
        let edge_b = ContentHash::from_bytes(b"coverage-edge-b");
        let edge_c = ContentHash::from_bytes(b"coverage-edge-c");
        let coverage_ab = ContentHash::from_bytes(b"coverage-a-b");
        let first_coverage = index.admit_coverage_map(coverage_ab, [edge_a, edge_b])?;
        assert!(first_coverage.admitted());
        assert_eq!(first_coverage.new_entries.len(), 2);
        let same_fingerprint = index.admit_coverage_map(coverage_ab, [edge_a, edge_b])?;
        assert!(same_fingerprint.redundant());
        assert_eq!(same_fingerprint.duplicate_entries.len(), 2);

        let interrupted_fingerprint = ContentHash::from_bytes(b"coverage-interrupted");
        let interrupted_a = ContentHash::from_bytes(b"coverage-interrupted-a");
        let interrupted_b = ContentHash::from_bytes(b"coverage-interrupted-b");
        let interrupted_path = index.coverage_fingerprint_path(&interrupted_fingerprint);
        let interrupted_parent = interrupted_path
            .parent()
            .ok_or_else(|| std::io::Error::other("coverage fingerprint path has no parent"))?;
        fs::create_dir_all(interrupted_parent)?;
        fs::write(
            &interrupted_path,
            coverage_fingerprint_record_material(
                &interrupted_fingerprint,
                &[interrupted_a, interrupted_b],
            ),
        )?;
        assert!(!index.coverage_path(&interrupted_a).exists());
        let repaired =
            index.admit_coverage_map(interrupted_fingerprint, [interrupted_a, interrupted_b])?;
        assert!(repaired.redundant());
        assert_eq!(repaired.duplicate_entries.len(), 2);
        assert!(index.coverage_path(&interrupted_a).exists());
        assert!(index.coverage_path(&interrupted_b).exists());

        let duplicate_coverage = index.admit_coverage_map(
            ContentHash::from_bytes(b"coverage-a-b-duplicate"),
            [edge_a, edge_b],
        )?;
        assert!(duplicate_coverage.redundant());
        assert_eq!(duplicate_coverage.duplicate_entries.len(), 2);
        let merged_coverage =
            index.admit_coverage_map(ContentHash::from_bytes(b"coverage-b-c"), [edge_b, edge_c])?;
        assert!(merged_coverage.admitted());
        assert_eq!(merged_coverage.new_entries, vec![edge_c]);
        assert_eq!(merged_coverage.duplicate_entries, vec![edge_b]);

        let reduction_fingerprint = ContentHash::from_bytes(b"symmetry-por-fingerprint");
        let representative = ContentHash::from_bytes(b"canonical-representative");
        let covered = ContentHash::from_bytes(b"covered-equivalent");
        let first_reduction =
            index.admit_reduction_fingerprint(reduction_fingerprint, representative)?;
        assert!(first_reduction.admitted());
        assert_eq!(first_reduction.representative, representative);
        let covered_reduction =
            index.admit_reduction_fingerprint(reduction_fingerprint, covered)?;
        assert!(covered_reduction.covered());
        assert_eq!(covered_reduction.representative, representative);
        assert_eq!(covered_reduction.covered, Some(covered));

        let frontier = SharedFrontier::new(temp.path().join("frontier"));
        let node_a = store.put(b"claim-anti-redundancy-a")?;
        let node_b = store.put(b"claim-anti-redundancy-b")?;
        frontier.admit(&node_a)?;
        frontier.admit(&node_b)?;
        let first_claim = frontier
            .claim_next(&FrontierClaimRequest::new("host-a", 1, 5))?
            .ok_or_else(|| std::io::Error::other("first host did not claim a frontier node"))?;
        let second_claim = frontier
            .claim_next(&FrontierClaimRequest::new("host-b", 2, 5))?
            .ok_or_else(|| std::io::Error::other("second host did not claim fallback node"))?;
        assert_ne!(first_claim.node, second_claim.node);
        assert!(!frontier.claimable_nodes(3)?.contains(&first_claim.node));

        Ok(())
    }

    #[test]
    fn campaign_seed_loads_self_contained_replay_artifacts()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let first = CampaignReplayArtifact::new(
            b"definition:partition-recovery".to_vec(),
            b"seed:0001".to_vec(),
            b"schedule:a,b,c".to_vec(),
        );
        let second = CampaignReplayArtifact::new(
            b"definition:crash-restart".to_vec(),
            b"seed:0002".to_vec(),
            b"schedule:x,y,z".to_vec(),
        );
        let corpus_root =
            campaign.persist_campaign_corpus([first.clone(), second.clone(), first.clone()])?;
        let manifest = CampaignManifest::new(
            corpus_root,
            campaign.persist_accumulated_coverage_map([])?,
            campaign.persist_findings_ledger([])?,
            ContentHash::from_bytes(b"genesis-pin"),
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1"),
        );

        let seeds = campaign.seed_next_run(&manifest, &manifest.provenance)?;

        assert_eq!(seeds.len(), 2);
        for seed in seeds {
            assert!(seed.reproduces_bit_identically());
            assert_eq!(
                campaign.read_replay_artifact(seed.artifact_hash)?,
                seed.artifact
            );
            assert!(
                seed.artifact
                    .replay_bytes()
                    .starts_with(b"format=crucible.campaign-replay-input.v1\n")
            );
        }

        Ok(())
    }

    #[test]
    fn campaign_coverage_ratchet_is_grow_only_union_crdt() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let edge_a = ContentHash::from_bytes(b"campaign-edge-a");
        let edge_b = ContentHash::from_bytes(b"campaign-edge-b");
        let edge_c = ContentHash::from_bytes(b"campaign-edge-c");
        let left = campaign.persist_accumulated_coverage_map([edge_a, edge_b])?;
        let right = campaign.persist_accumulated_coverage_map([edge_b, edge_c])?;

        let merged = campaign.merge_accumulated_coverage_maps(left, right)?;
        let reverse = campaign.merge_accumulated_coverage_maps(right, left)?;
        let duplicate = campaign.merge_accumulated_coverage_maps(merged, left)?;
        let delta = campaign.accumulated_coverage_delta(merged, [edge_a, edge_c])?;
        let novel = campaign.accumulated_coverage_delta(
            merged,
            [edge_a, ContentHash::from_bytes(b"campaign-edge-d")],
        )?;
        let mut expected_edges = vec![edge_a, edge_b, edge_c];
        expected_edges.sort();
        let mut expected_known = vec![edge_a, edge_c];
        expected_known.sort();

        assert_eq!(merged, reverse);
        assert_eq!(duplicate, merged);
        assert_eq!(campaign.accumulated_coverage_edges(merged)?, expected_edges);
        assert!(!delta.is_novel());
        assert_eq!(delta.known_edges, expected_known);
        assert!(novel.is_novel());
        assert_eq!(novel.new_edges.len(), 1);

        Ok(())
    }

    #[test]
    fn campaign_findings_ledger_accumulates_and_deduplicates()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let artifact_a = CampaignReplayArtifact::new(
            b"definition:finding-a".to_vec(),
            b"seed:a".to_vec(),
            b"schedule:a".to_vec(),
        );
        let artifact_b = CampaignReplayArtifact::new(
            b"definition:finding-b".to_vec(),
            b"seed:b".to_vec(),
            b"schedule:b".to_vec(),
        );
        let finding_a =
            CampaignFinding::new(ContentHash::from_bytes(b"failure-a"), artifact_a.clone());
        let finding_a_rediscovered = CampaignFinding::new(
            ContentHash::from_bytes(b"failure-a-rediscovered"),
            artifact_a.clone(),
        );
        let finding_b =
            CampaignFinding::new(ContentHash::from_bytes(b"failure-b"), artifact_b.clone());
        let artifact_a_hash = campaign.persist_replay_artifact(&artifact_a)?;
        let left = campaign
            .persist_findings_ledger([finding_a.clone(), finding_a_rediscovered.clone()])?;
        let right = campaign.persist_findings_ledger([finding_a_rediscovered, finding_b])?;

        let merged = campaign.merge_findings_ledgers(left, right)?;
        let entries = campaign.findings_ledger_entries(merged)?;

        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries
                .iter()
                .filter(|entry| entry.artifact_hash == artifact_a_hash)
                .count(),
            1
        );
        for entry in entries {
            let artifact = campaign.read_replay_artifact(entry.artifact_hash)?;
            assert!(entry.reproduces_bit_identically(&artifact));
        }

        Ok(())
    }

    #[test]
    fn campaign_gc_is_rooted_at_manifest_roots_and_sweeps_unpinned_candidates()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let corpus_artifact = CampaignReplayArtifact::new(
            b"definition:gc-corpus".to_vec(),
            b"seed:gc-corpus".to_vec(),
            b"schedule:gc-corpus".to_vec(),
        );
        let finding_artifact = CampaignReplayArtifact::new(
            b"definition:gc-finding".to_vec(),
            b"seed:gc-finding".to_vec(),
            b"schedule:gc-finding".to_vec(),
        );
        let corpus_artifact_hash = campaign.persist_replay_artifact(&corpus_artifact)?;
        let finding_artifact_hash = campaign.persist_replay_artifact(&finding_artifact)?;
        let coverage_edge = campaign.manifest_store().put(b"coverage-edge-object")?;
        let abandoned = campaign
            .manifest_store()
            .put(b"abandoned-unpinned-campaign-object")?;
        let genesis_pin = campaign.manifest_store().put(b"campaign-genesis-pin")?;
        let corpus_root = campaign.persist_campaign_corpus([corpus_artifact])?;
        let coverage_map_root = campaign.persist_accumulated_coverage_map([coverage_edge])?;
        let findings_root = campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"gc-finding-fingerprint"),
            finding_artifact,
        )])?;
        let finding_entry = campaign
            .findings_ledger_entries(findings_root)?
            .into_iter()
            .next()
            .ok_or_else(|| std::io::Error::other("finding ledger did not persist an entry"))?;
        let manifest = CampaignManifest::new(
            corpus_root,
            coverage_map_root,
            findings_root,
            genesis_pin,
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1"),
        );

        let candidates = [
            corpus_root,
            coverage_map_root,
            findings_root,
            genesis_pin,
            corpus_artifact_hash,
            coverage_edge,
            finding_artifact_hash,
            finding_entry.finding_hash,
            abandoned,
        ];
        let plan = campaign.campaign_gc_plan(&manifest, candidates)?;

        assert_eq!(
            plan.roots.root_set(),
            BTreeSet::from([corpus_root, coverage_map_root, findings_root, genesis_pin])
        );
        assert!(plan.retained_objects.contains(&corpus_artifact_hash));
        assert!(plan.retained_objects.contains(&coverage_edge));
        assert!(plan.retained_objects.contains(&finding_artifact_hash));
        assert!(plan.retained_objects.contains(&finding_entry.finding_hash));
        assert_eq!(plan.sweep_candidates, BTreeSet::from([abandoned]));

        let report = campaign.garbage_collect_campaign_candidates(&manifest, candidates)?;
        assert_eq!(report.swept_objects, BTreeSet::from([abandoned]));
        assert!(!campaign.manifest_store().has(&abandoned)?);
        assert!(campaign.manifest_store().has(&corpus_root)?);
        assert!(campaign.manifest_store().has(&findings_root)?);
        assert_eq!(
            campaign
                .seed_next_run(&manifest, &manifest.provenance)?
                .len(),
            1
        );
        assert_eq!(campaign.findings_ledger_entries(findings_root)?.len(), 1);

        Ok(())
    }

    #[test]
    fn campaign_fat_to_thin_eviction_preserves_checkpoint_value() {
        let checkpoint = ContentHash::from_bytes(b"checkpoint-value");
        let parent = ContentHash::from_bytes(b"checkpoint-parent");
        let schedule_delta = ContentHash::from_bytes(b"checkpoint-schedule-delta");
        let materialization = ContentHash::from_bytes(b"cache-only-materialization");
        let fat = CampaignCheckpointMaterialization::fat(
            checkpoint,
            parent,
            schedule_delta,
            materialization,
        );

        let eviction = fat.evict_to_thin();

        assert!(eviction.preserves_value());
        assert_eq!(eviction.evicted_materialization, Some(materialization));
        assert_eq!(eviction.after.checkpoint, checkpoint);
        assert_eq!(eviction.after.parent, parent);
        assert_eq!(eviction.after.schedule_delta, schedule_delta);
        assert!(eviction.after.materialization.is_none());
    }

    #[test]
    fn campaign_corpus_retention_is_deterministic_seeded_cap()
    -> Result<(), Box<dyn std::error::Error>> {
        let left_temp = tempfile::tempdir()?;
        let right_temp = tempfile::tempdir()?;
        let left_campaign = SharedCampaignStore::new(left_temp.path());
        let right_campaign = SharedCampaignStore::new(right_temp.path());
        let artifacts = [
            CampaignReplayArtifact::new(
                b"definition:retention-a".to_vec(),
                b"seed:a".to_vec(),
                b"schedule:a".to_vec(),
            ),
            CampaignReplayArtifact::new(
                b"definition:retention-b".to_vec(),
                b"seed:b".to_vec(),
                b"schedule:b".to_vec(),
            ),
            CampaignReplayArtifact::new(
                b"definition:retention-c".to_vec(),
                b"seed:c".to_vec(),
                b"schedule:c".to_vec(),
            ),
            CampaignReplayArtifact::new(
                b"definition:retention-d".to_vec(),
                b"seed:d".to_vec(),
                b"schedule:d".to_vec(),
            ),
        ];
        let left_corpus = left_campaign.persist_campaign_corpus(artifacts.iter().cloned())?;
        let right_corpus =
            right_campaign.persist_campaign_corpus(artifacts.iter().rev().cloned())?;
        let policy =
            CampaignCorpusRetentionPolicy::new(2, ContentHash::from_bytes(b"retention-seed"));
        let zero_cap_policy =
            CampaignCorpusRetentionPolicy::new(0, ContentHash::from_bytes(b"retention-seed"));

        let left_retention = left_campaign.retain_campaign_corpus_under_cap(left_corpus, policy)?;
        let left_retention_repeat =
            left_campaign.retain_campaign_corpus_under_cap(left_corpus, policy)?;
        let right_retention =
            right_campaign.retain_campaign_corpus_under_cap(right_corpus, policy)?;
        assert!(matches!(
            left_campaign.retain_campaign_corpus_under_cap(left_corpus, zero_cap_policy),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign corpus retention cap must be greater than zero",
                ..
            })
        ));

        assert_eq!(left_corpus, right_corpus);
        assert_eq!(left_retention, left_retention_repeat);
        assert_eq!(left_retention.retained_root, right_retention.retained_root);
        assert_eq!(left_retention.retained_artifacts.len(), 2);
        assert_eq!(left_retention.evicted_artifacts.len(), 2);
        assert_eq!(
            left_campaign
                .seed_next_run_from_prior_corpus(left_retention.retained_root)?
                .len(),
            2
        );

        let coverage_root = left_campaign.persist_accumulated_coverage_map([])?;
        let finding_artifact = artifacts
            .first()
            .cloned()
            .ok_or_else(|| std::io::Error::other("missing retention artifact"))?;
        let findings_root = left_campaign.persist_findings_ledger([CampaignFinding::new(
            ContentHash::from_bytes(b"retention-finding"),
            finding_artifact,
        )])?;
        let genesis_pin = left_campaign
            .manifest_store()
            .put(b"retention-genesis-pin")?;
        let provenance =
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1");
        let full_manifest = CampaignManifest::new(
            left_corpus,
            coverage_root,
            findings_root,
            genesis_pin,
            provenance.clone(),
        );
        let retained_manifest = CampaignManifest::new(
            left_retention.retained_root,
            coverage_root,
            findings_root,
            genesis_pin,
            provenance.clone(),
        );
        let first_head = match left_campaign.compare_and_swap_head(None, &full_manifest)? {
            CampaignCasOutcome::Advanced(head) => head,
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        };

        assert!(matches!(
            left_campaign.compare_and_swap_head(Some(first_head.manifest_hash), &retained_manifest),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign corpus advance would drop a prior seed artifact",
                ..
            })
        ));
        assert!(matches!(
            left_campaign.compare_and_swap_head_with_retention(
                Some(first_head.manifest_hash),
                &retained_manifest,
                CampaignCorpusRetentionPolicy::new(
                    1,
                    ContentHash::from_bytes(b"retention-seed-mismatch")
                ),
            ),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign corpus retention policy does not match authorized retention policy",
                ..
            })
        ));

        let retained_head = match left_campaign.compare_and_swap_head_with_retention(
            Some(first_head.manifest_hash),
            &retained_manifest,
            policy,
        )? {
            CampaignCasOutcome::Advanced(head) => {
                assert_eq!(head.manifest.corpus_root, left_retention.retained_root);
                assert_eq!(head.manifest.findings_root, findings_root);
                head
            }
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("retention campaign CAS lost").into());
            }
        };
        assert!(matches!(
            left_campaign.compare_and_swap_head(Some(retained_head.manifest_hash), &full_manifest),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign corpus retention roots require explicit retention policy",
                ..
            })
        ));
        assert_eq!(
            left_campaign.findings_ledger_entries(findings_root)?.len(),
            1
        );

        Ok(())
    }

    #[test]
    fn campaign_retention_merge_retry_does_not_expand_over_cap()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let artifact_a = CampaignReplayArtifact::new(
            b"definition:merge-retention-a".to_vec(),
            b"seed:a".to_vec(),
            b"schedule:a".to_vec(),
        );
        let artifact_b = CampaignReplayArtifact::new(
            b"definition:merge-retention-b".to_vec(),
            b"seed:b".to_vec(),
            b"schedule:b".to_vec(),
        );
        let artifact_c = CampaignReplayArtifact::new(
            b"definition:merge-retention-c".to_vec(),
            b"seed:c".to_vec(),
            b"schedule:c".to_vec(),
        );
        let edge = ContentHash::from_bytes(b"merge-retention-edge");
        let coverage_root = campaign.persist_accumulated_coverage_map([edge])?;
        let findings_root = campaign.persist_findings_ledger([])?;
        let genesis_pin = campaign.manifest_store().put(b"merge-retention-genesis")?;
        let provenance =
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1");
        let corpus_root =
            campaign.persist_campaign_corpus([artifact_a.clone(), artifact_b.clone()])?;
        let retention = campaign.retain_campaign_corpus_under_cap(
            corpus_root,
            CampaignCorpusRetentionPolicy::new(1, ContentHash::from_bytes(b"merge-retention-seed")),
        )?;
        let full_manifest = CampaignManifest::new(
            corpus_root,
            coverage_root,
            findings_root,
            genesis_pin,
            provenance.clone(),
        );
        let retained_manifest = CampaignManifest::new(
            retention.retained_root,
            coverage_root,
            findings_root,
            genesis_pin,
            provenance.clone(),
        );
        let head = match campaign.compare_and_swap_head(None, &full_manifest)? {
            CampaignCasOutcome::Advanced(head) => head,
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        };
        match campaign.compare_and_swap_head_with_retention(
            Some(head.manifest_hash),
            &retained_manifest,
            CampaignCorpusRetentionPolicy::new(1, ContentHash::from_bytes(b"merge-retention-seed")),
        )? {
            CampaignCasOutcome::Advanced(_) => {}
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("retention campaign CAS lost").into());
            }
        }
        let competing_manifest = CampaignManifest::new(
            campaign.persist_campaign_corpus([artifact_c])?,
            coverage_root,
            findings_root,
            genesis_pin,
            provenance,
        );

        assert!(matches!(
            campaign.advance_head_with_merge(&competing_manifest, 1),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign corpus retention roots require explicit retention policy",
                ..
            })
        ));
        assert_eq!(
            campaign
                .seed_next_run_from_prior_corpus(retention.retained_root)?
                .len(),
            1
        );

        Ok(())
    }

    #[test]
    fn campaign_head_merge_unions_typed_campaign_roots() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let artifact_a = CampaignReplayArtifact::new(
            b"definition:a".to_vec(),
            b"seed:a".to_vec(),
            b"s:a".to_vec(),
        );
        let artifact_b = CampaignReplayArtifact::new(
            b"definition:b".to_vec(),
            b"seed:b".to_vec(),
            b"s:b".to_vec(),
        );
        let edge_a = ContentHash::from_bytes(b"typed-edge-a");
        let edge_b = ContentHash::from_bytes(b"typed-edge-b");
        let finding_a = CampaignFinding::new(
            ContentHash::from_bytes(b"typed-finding-a"),
            artifact_a.clone(),
        );
        let finding_b = CampaignFinding::new(
            ContentHash::from_bytes(b"typed-finding-b"),
            artifact_b.clone(),
        );
        let provenance =
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1");
        let first = CampaignManifest::new(
            campaign.persist_campaign_corpus([artifact_a])?,
            campaign.persist_accumulated_coverage_map([edge_a])?,
            campaign.persist_findings_ledger([finding_a])?,
            ContentHash::from_bytes(b"genesis-pin"),
            provenance.clone(),
        );
        let second = CampaignManifest::new(
            campaign.persist_campaign_corpus([artifact_b])?,
            campaign.persist_accumulated_coverage_map([edge_b])?,
            campaign.persist_findings_ledger([finding_b])?,
            ContentHash::from_bytes(b"genesis-pin"),
            provenance,
        );

        match campaign.compare_and_swap_head(None, &first)? {
            CampaignCasOutcome::Advanced(_) => {}
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        }
        let report = campaign.advance_head_with_merge(&second, 3)?;
        let mut expected_edges = vec![edge_a, edge_b];
        expected_edges.sort();

        assert_eq!(
            campaign
                .seed_next_run(&report.head.manifest, &report.head.manifest.provenance)?
                .len(),
            2
        );
        assert_eq!(
            campaign.accumulated_coverage_edges(report.head.manifest.coverage_map_root)?,
            expected_edges
        );
        assert_eq!(
            campaign
                .findings_ledger_entries(report.head.manifest.findings_root)?
                .len(),
            2
        );

        Ok(())
    }

    #[test]
    fn campaign_head_cas_rejects_typed_root_regression() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let artifact_a = CampaignReplayArtifact::new(
            b"definition:regression-a".to_vec(),
            b"seed:a".to_vec(),
            b"schedule:a".to_vec(),
        );
        let artifact_b = CampaignReplayArtifact::new(
            b"definition:regression-b".to_vec(),
            b"seed:b".to_vec(),
            b"schedule:b".to_vec(),
        );
        let edge_a = ContentHash::from_bytes(b"regression-edge-a");
        let edge_b = ContentHash::from_bytes(b"regression-edge-b");
        let finding_a = CampaignFinding::new(
            ContentHash::from_bytes(b"regression-finding-a"),
            artifact_a.clone(),
        );
        let finding_b = CampaignFinding::new(
            ContentHash::from_bytes(b"regression-finding-b"),
            artifact_b.clone(),
        );
        let provenance =
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1");
        let full_corpus = campaign.persist_campaign_corpus([artifact_a.clone(), artifact_b])?;
        let full_coverage = campaign.persist_accumulated_coverage_map([edge_a, edge_b])?;
        let full_findings =
            campaign.persist_findings_ledger([finding_a.clone(), finding_b.clone()])?;
        let first = CampaignManifest::new(
            full_corpus,
            full_coverage,
            full_findings,
            ContentHash::from_bytes(b"genesis-pin"),
            provenance.clone(),
        );
        let corpus_regressed = CampaignManifest::new(
            campaign.persist_campaign_corpus([artifact_a.clone()])?,
            full_coverage,
            full_findings,
            ContentHash::from_bytes(b"genesis-pin"),
            provenance.clone(),
        );
        let coverage_regressed = CampaignManifest::new(
            full_corpus,
            campaign.persist_accumulated_coverage_map([edge_a])?,
            full_findings,
            ContentHash::from_bytes(b"genesis-pin"),
            provenance.clone(),
        );
        let findings_regressed = CampaignManifest::new(
            full_corpus,
            full_coverage,
            campaign.persist_findings_ledger([finding_a])?,
            ContentHash::from_bytes(b"genesis-pin"),
            provenance.clone(),
        );

        let first_head = match campaign.compare_and_swap_head(None, &first)? {
            CampaignCasOutcome::Advanced(head) => head,
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        };

        assert!(matches!(
            campaign.compare_and_swap_head(Some(first_head.manifest_hash), &corpus_regressed),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign corpus advance would drop a prior seed artifact",
                ..
            })
        ));
        assert!(matches!(
            campaign.compare_and_swap_head(Some(first_head.manifest_hash), &coverage_regressed),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign coverage-map advance would reduce accumulated coverage",
                ..
            })
        ));
        assert!(matches!(
            campaign.compare_and_swap_head(Some(first_head.manifest_hash), &findings_regressed),
            Err(CasError::InvalidCampaignRecord {
                reason: "campaign findings advance would drop a prior finding artifact",
                ..
            })
        ));
        assert_eq!(
            campaign
                .read_head()?
                .ok_or_else(|| std::io::Error::other("campaign head missing"))?
                .manifest_hash,
            first_head.manifest_hash
        );

        Ok(())
    }

    #[test]
    fn campaign_manifest_is_content_addressed_with_single_head()
    -> Result<(), Box<dyn std::error::Error>> {
        let left = tempfile::tempdir()?;
        let right = tempfile::tempdir()?;
        let left_store = SharedCampaignStore::new(left.path());
        let right_store = SharedCampaignStore::new(right.path());
        let manifest =
            campaign_manifest_fixture(&left_store, "corpus-a", "coverage-a", "findings-a")?;
        let right_manifest =
            campaign_manifest_fixture(&right_store, "corpus-a", "coverage-a", "findings-a")?;

        let left_hash = left_store.persist_manifest(&manifest)?;
        let right_hash = right_store.persist_manifest(&right_manifest)?;

        assert_eq!(left_hash, right_hash);
        assert_eq!(manifest, right_manifest);
        assert_eq!(left_store.head_path(), left.path().join("campaign-head"));
        assert_ne!(
            left_store.head_path(),
            left_store.manifest_store().object_path(&left_hash)
        );

        Ok(())
    }

    #[test]
    fn campaign_head_cas_loses_only_bookkeeping() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let first = campaign_manifest_fixture(&campaign, "corpus-a", "coverage-a", "findings-a")?;
        let second = campaign_manifest_fixture(&campaign, "corpus-b", "coverage-b", "findings-b")?;

        let first_head = match campaign.compare_and_swap_head(None, &first)? {
            CampaignCasOutcome::Advanced(head) => head,
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        };
        let lost = match campaign.compare_and_swap_head(None, &second)? {
            CampaignCasOutcome::LostUpdate {
                current,
                proposed_manifest_hash,
                ..
            } => {
                assert_eq!(current, Some(first_head.manifest_hash));
                assert!(campaign.manifest_store().has(&proposed_manifest_hash)?);
                proposed_manifest_hash
            }
            CampaignCasOutcome::Advanced(_) => {
                return Err(std::io::Error::other("stale campaign CAS advanced").into());
            }
        };
        assert_eq!(
            campaign
                .read_head()?
                .ok_or_else(|| std::io::Error::other("campaign head missing"))?
                .manifest_hash,
            first_head.manifest_hash
        );
        assert!(campaign.manifest_store().has(&lost)?);

        Ok(())
    }

    #[test]
    fn campaign_head_ignores_torn_final_log_entry() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let first = campaign_manifest_fixture(&campaign, "corpus-a", "coverage-a", "findings-a")?;
        let second = campaign_manifest_fixture(&campaign, "corpus-b", "coverage-b", "findings-b")?;

        let first_head = match campaign.compare_and_swap_head(None, &first)? {
            CampaignCasOutcome::Advanced(head) => head,
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        };
        let mut head_file = OpenOptions::new().append(true).open(campaign.head_path())?;
        head_file.write_all(b"entry generation=2 manifest=partial")?;
        drop(head_file);

        assert_eq!(
            campaign
                .read_head()?
                .ok_or_else(|| std::io::Error::other("campaign head missing after torn append"))?
                .manifest_hash,
            first_head.manifest_hash
        );
        match campaign.compare_and_swap_head(Some(first_head.manifest_hash), &second)? {
            CampaignCasOutcome::Advanced(head) => {
                assert_ne!(head.manifest_hash, first_head.manifest_hash);
                assert_eq!(head.manifest, second);
            }
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("campaign CAS lost after torn append").into());
            }
        }

        Ok(())
    }

    #[test]
    fn campaign_head_recovers_from_torn_initial_log_entry() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let first = campaign_manifest_fixture(&campaign, "corpus-a", "coverage-a", "findings-a")?;
        fs::write(campaign.head_path(), b"entry generation=1 manifest=partial")?;

        match campaign.compare_and_swap_head(None, &first)? {
            CampaignCasOutcome::Advanced(head) => {
                assert_eq!(head.manifest, first);
            }
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(
                    std::io::Error::other("campaign CAS lost after torn initial log").into(),
                );
            }
        }
        assert!(campaign.read_head()?.is_some());

        Ok(())
    }

    #[test]
    fn campaign_head_cas_serializes_contending_writers() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let workers = 12;
        let barrier = Arc::new(Barrier::new(workers));
        let mut manifests = Vec::new();
        for worker in 0..workers {
            manifests.push(campaign_manifest_fixture(
                &campaign,
                &format!("corpus-{worker}"),
                &format!("coverage-{worker}"),
                &format!("findings-{worker}"),
            )?);
        }

        let mut handles = Vec::new();
        for manifest in manifests {
            let campaign = campaign.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                campaign.compare_and_swap_head(None, &manifest)
            }));
        }

        let mut advanced = 0;
        let mut lost = 0;
        for handle in handles {
            match handle
                .join()
                .map_err(|_| std::io::Error::other("campaign CAS worker panicked"))??
            {
                CampaignCasOutcome::Advanced(_) => advanced += 1,
                CampaignCasOutcome::LostUpdate {
                    proposed_manifest_hash,
                    ..
                } => {
                    lost += 1;
                    assert!(campaign.manifest_store().has(&proposed_manifest_hash)?);
                }
            }
        }

        assert_eq!(advanced, 1);
        assert_eq!(lost, workers - 1);
        assert!(campaign.read_head()?.is_some());

        Ok(())
    }

    #[test]
    fn campaign_head_read_merge_retry_advances_union_manifest()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let campaign = SharedCampaignStore::new(temp.path());
        let first = campaign_manifest_fixture(&campaign, "corpus-a", "coverage-a", "findings-a")?;
        let second = campaign_manifest_fixture(&campaign, "corpus-b", "coverage-b", "findings-b")?;
        let first_hash = campaign.persist_manifest(&first)?;

        match campaign.compare_and_swap_head(None, &first)? {
            CampaignCasOutcome::Advanced(_) => {}
            CampaignCasOutcome::LostUpdate { .. } => {
                return Err(std::io::Error::other("initial campaign CAS lost").into());
            }
        }
        let report = campaign.advance_head_with_merge(&second, 3)?;

        assert_eq!(report.attempts, 1);
        assert_ne!(report.head.manifest_hash, first_hash);
        let expected_corpus =
            campaign_root_merge_hash("corpus", first.corpus_root, second.corpus_root);
        let expected_coverage = campaign_root_merge_hash(
            "coverage-map",
            first.coverage_map_root,
            second.coverage_map_root,
        );
        let expected_findings =
            campaign_root_merge_hash("findings", first.findings_root, second.findings_root);
        assert_eq!(report.head.manifest.corpus_root, expected_corpus);
        assert_eq!(report.head.manifest.coverage_map_root, expected_coverage);
        assert_eq!(report.head.manifest.findings_root, expected_findings);
        assert!(campaign.manifest_store().has(&expected_corpus)?);
        assert!(campaign.manifest_store().has(&expected_coverage)?);
        assert!(campaign.manifest_store().has(&expected_findings)?);
        assert_eq!(report.head.manifest.genesis_pin, first.genesis_pin);
        assert_eq!(report.head.manifest.provenance, first.provenance);
        assert_eq!(
            campaign
                .read_head()?
                .ok_or_else(|| std::io::Error::other("campaign head missing"))?
                .manifest_hash,
            report.head.manifest_hash
        );

        Ok(())
    }

    fn campaign_manifest_fixture(
        campaign: &SharedCampaignStore,
        corpus: &str,
        coverage: &str,
        findings: &str,
    ) -> Result<CampaignManifest, CasError> {
        Ok(CampaignManifest::new(
            campaign_root_fixture(campaign, "corpus", corpus)?,
            campaign_root_fixture(campaign, "coverage-map", coverage)?,
            campaign_root_fixture(campaign, "findings", findings)?,
            ContentHash::from_bytes(b"genesis-pin"),
            CampaignProvenance::new("crucible-test", "qemu-test+series", "shmem:1,gh:1,rpc:1"),
        ))
    }

    fn campaign_root_fixture(
        campaign: &SharedCampaignStore,
        label: &str,
        value: &str,
    ) -> Result<ContentHash, CasError> {
        campaign.manifest_store().put(
            format!("format=crucible.campaign-root-fixture.v1\nlabel={label}\nvalue={value}\n")
                .as_bytes(),
        )
    }

    #[test]
    fn shared_frontier_affinity_reorders_without_filtering()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let store = SharedDagStore::new(temp.path().join("objects"));
        let frontier = SharedFrontier::new(temp.path().join("frontier"));
        for payload in [b"frontier-a", b"frontier-b", b"frontier-c"] {
            frontier.admit(&store.put(payload)?)?;
        }

        let without_affinity = frontier.ordered_claimable_nodes(1, &SoftHashAffinity::off())?;
        let preferred_node = without_affinity
            .last()
            .copied()
            .ok_or_else(|| std::io::Error::other("frontier should contain nodes"))?;
        let with_affinity =
            frontier.ordered_claimable_nodes(1, &SoftHashAffinity::prefer([preferred_node]))?;

        let mut without_set = without_affinity.clone();
        without_set.sort();
        let mut with_set = with_affinity.clone();
        with_set.sort();
        assert_eq!(with_set, without_set);
        assert_eq!(with_affinity.first().copied(), Some(preferred_node));

        let lease = frontier
            .claim_next(
                &FrontierClaimRequest::new("host-affine", 1, 10)
                    .with_affinity(SoftHashAffinity::prefer([preferred_node])),
            )?
            .ok_or_else(|| std::io::Error::other("affine claim did not lease a node"))?;
        assert_eq!(lease.node, preferred_node);
        let remaining = frontier.claimable_nodes(2)?;
        assert_eq!(remaining.len(), without_set.len() - 1);
        assert!(!remaining.contains(&preferred_node));

        Ok(())
    }

    #[test]
    fn invalidation_is_gated_by_dependency_hash_changes() {
        let kernel_a = ContentHash::from_bytes(b"kernel-a");
        let kernel_b = ContentHash::from_bytes(b"kernel-b");
        let rootfs = ContentHash::from_bytes(b"rootfs");

        let mut baseline = DependencySnapshot::new();
        baseline.insert("kernel", kernel_a);
        baseline.insert("rootfs", rootfs);
        let query = InvalidationQuery::new(baseline);

        let mut unchanged = DependencySnapshot::new();
        unchanged.insert("kernel", kernel_a);
        unchanged.insert("rootfs", rootfs);
        assert!(!query.is_invalid(&unchanged));

        let mut changed = DependencySnapshot::new();
        changed.insert("kernel", kernel_b);
        changed.insert("rootfs", rootfs);
        let decision = query.evaluate(&changed);
        assert!(decision.is_invalid());
        assert_eq!(
            decision.changed_inputs().get("kernel"),
            Some(&DependencyChange {
                before: Some(kernel_a),
                after: Some(kernel_b),
            })
        );
    }
}
