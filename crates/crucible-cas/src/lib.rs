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
//! [`InvalidationDecision`]. [`content_store`] owns RFC-0016's streaming,
//! domain-separated immutable-blob and mutable-ref contracts plus its closed
//! composition-graph validator. [`content_envelope`] owns the generic canonical
//! child-bearing object format used by storage, transfer, and closure walkers
//! without depending on campaign semantics.

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

#[path = "cas/campaign_codec.rs"]
mod campaign_codec;
#[path = "cas/campaign_model.rs"]
mod campaign_model;
#[path = "cas/campaign_store.rs"]
mod campaign_store;
#[cfg(test)]
#[path = "cas/tests.rs"]
mod campaign_tests;
#[path = "cas/invalidation.rs"]
mod invalidation;

use campaign_codec::*;
pub use campaign_model::*;
pub use campaign_store::*;
pub use invalidation::*;

pub mod content_envelope;
pub mod content_store;
