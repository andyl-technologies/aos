//! Content-addressed storage primitives for Crucible.
//!
//! `crucible-cas` owns the small standalone substrate required by RFC-0010:
//! BLAKE3 content keys, a minimal `put`/`get`/`has` store interface, local and
//! in-memory implementations, a fleet-visible shared implementation, and a
//! dependency-gated invalidation query. The crate intentionally has no
//! dependency on RFC-0007 `ratchet` crates; any future shared substrate must
//! adapt behind this crate's public interface and pass `gate:content-address`
//! and `gate:replay-oracle` unchanged.
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
//! [`SoftHashAffinity`], and the invalidation types [`DependencySnapshot`],
//! [`InvalidationQuery`], and [`InvalidationDecision`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

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
                    let node = ContentHash::from_hex(name).ok_or_else(|| {
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
