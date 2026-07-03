//! Content-addressed storage primitives for Crucible.
//!
//! `crucible-cas` owns the small standalone substrate required by RFC-0010:
//! BLAKE3 content keys, a minimal `put`/`get`/`has` store interface, local and
//! in-memory implementations, and a dependency-gated invalidation query. The
//! crate intentionally has no dependency on RFC-0007 `ratchet` crates; any
//! future shared substrate must adapt behind this crate's public interface and
//! pass `gate:content-address` and `gate:replay-oracle` unchanged.
//!
//! Future RFC-0007 integration marker: RFC-0007 is the future home for a shared
//! content-addressed store plus dependency-gated invalidation substrate. The
//! narrow interface is exactly [`DagStore::put`], [`DagStore::get`],
//! [`DagStore::has`], and [`InvalidationQuery::evaluate`]. The future-merge plan
//! is a thin adapter behind that unchanged interface; no Crucible ABI or determinism
//! contract may change, and the adapter replaces these internals only after
//! `gate:content-address`, `gate:replay-oracle`, and `gate:e2e-determinism` pass
//! unchanged. Until then, no RFC-0007 dependency exists.
//!
//! Module map: the crate root owns [`ContentHash`], [`DagStore`],
//! [`MemoryDagStore`], [`LocalDagStore`], and the invalidation types
//! [`DependencySnapshot`], [`InvalidationQuery`], and [`InvalidationDecision`].

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

use std::collections::btree_map::Entry;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

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

#[cfg(test)]
mod tests {
    use super::*;

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
