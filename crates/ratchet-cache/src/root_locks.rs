//! Same-process cache-root lock registry.
//!
//! Persistent cache adapters need several mutexes that are shared by all handles
//! opened on the same canonical cache root. This module owns the generic
//! process-local weak registry and the slot mutexes. It is not a durable or
//! cross-process lock protocol.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};

use thiserror::Error;

/// A same-root lock slot.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CacheRootLockSlot {
    /// Serializes root schema/open initialization.
    Open,
    /// Serializes `values/` blob-store writes and maintenance.
    Values,
    /// Serializes `files/` blob-store writes and maintenance.
    Files,
    /// Serializes file-artifact sidecar writes.
    FileArtifacts,
    /// Serializes parse-artifact sidecar writes.
    ParseArtifacts,
    /// Serializes demand-node metadata sidecar writes.
    NodeMetadata,
    /// Serializes demand-node trace sidecar writes.
    NodeTraces,
}

/// Same-process mutexes for one canonical cache root.
#[derive(Debug)]
pub struct CacheRootLocks {
    root: PathBuf,
    open: Mutex<()>,
    values: Mutex<()>,
    files: Mutex<()>,
    file_artifacts: Mutex<()>,
    parse_artifacts: Mutex<()>,
    node_metadata: Mutex<()>,
    node_traces: Mutex<()>,
}

impl CacheRootLocks {
    fn new(root: PathBuf) -> Self {
        Self {
            root,
            open: Mutex::new(()),
            values: Mutex::new(()),
            files: Mutex::new(()),
            file_artifacts: Mutex::new(()),
            parse_artifacts: Mutex::new(()),
            node_metadata: Mutex::new(()),
            node_traces: Mutex::new(()),
        }
    }

    /// Returns the canonical cache root for this lock set.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Locks `slot`.
    ///
    /// # Errors
    ///
    /// Returns [`CacheRootLockError::Poisoned`] if the selected mutex is poisoned.
    pub fn lock(&self, slot: CacheRootLockSlot) -> Result<MutexGuard<'_, ()>, CacheRootLockError> {
        self.slot(slot)
            .lock()
            .map_err(|_| CacheRootLockError::Poisoned { slot })
    }

    fn slot(&self, slot: CacheRootLockSlot) -> &Mutex<()> {
        match slot {
            CacheRootLockSlot::Open => &self.open,
            CacheRootLockSlot::Values => &self.values,
            CacheRootLockSlot::Files => &self.files,
            CacheRootLockSlot::FileArtifacts => &self.file_artifacts,
            CacheRootLockSlot::ParseArtifacts => &self.parse_artifacts,
            CacheRootLockSlot::NodeMetadata => &self.node_metadata,
            CacheRootLockSlot::NodeTraces => &self.node_traces,
        }
    }
}

/// A same-root lock operation failed.
#[derive(Debug, Error)]
pub enum CacheRootLockError {
    /// A selected lock slot was poisoned.
    #[error("cache-root lock slot {slot:?} is poisoned")]
    Poisoned {
        /// The lock slot that could not be acquired.
        slot: CacheRootLockSlot,
    },
}

/// The process-local root lock registry could not return a lock set.
#[derive(Debug, Error)]
pub enum CacheRootLockRegistryError {
    /// The cache root could not be canonicalized.
    #[error("failed to canonicalize cache root {path:?}")]
    CanonicalizeRoot {
        /// The requested root path.
        path: PathBuf,
        /// The underlying filesystem error.
        #[source]
        source: std::io::Error,
    },
    /// The weak registry mutex was poisoned.
    #[error("cache-root lock registry is poisoned")]
    RegistryPoisoned,
}

static CACHE_ROOT_LOCK_REGISTRY: OnceLock<Mutex<BTreeMap<PathBuf, Weak<CacheRootLocks>>>> =
    OnceLock::new();

/// Returns the same-process lock set for `root`.
///
/// `root` is canonicalized before lookup, so distinct paths to the same live
/// directory share the same lock set while at least one strong reference to that
/// set remains.
///
/// # Errors
///
/// Returns [`CacheRootLockRegistryError`] if `root` cannot be canonicalized or
/// the process-local weak registry is poisoned.
pub fn locks_for_root(root: &Path) -> Result<Arc<CacheRootLocks>, CacheRootLockRegistryError> {
    let canonical_root =
        fs::canonicalize(root).map_err(|source| CacheRootLockRegistryError::CanonicalizeRoot {
            path: root.to_path_buf(),
            source,
        })?;
    let registry = CACHE_ROOT_LOCK_REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut locks = registry
        .lock()
        .map_err(|_| CacheRootLockRegistryError::RegistryPoisoned)?;
    locks.retain(|_, candidate| candidate.strong_count() > 0);
    if let Some(existing) = locks.get(&canonical_root).and_then(Weak::upgrade) {
        return Ok(existing);
    }

    let created = Arc::new(CacheRootLocks::new(canonical_root.clone()));
    locks.insert(canonical_root, Arc::downgrade(&created));
    Ok(created)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_ID: AtomicU64 = AtomicU64::new(0);

    fn temp_root(name: &str) -> PathBuf {
        let nonce = TEST_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ratchet-cache-root-locks-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn locks_for_root_reuses_canonical_root_lock_set() {
        let root = temp_root("reuse");
        fs::create_dir_all(&root).expect("root creates");

        let first = locks_for_root(&root).expect("first locks load");
        let second = locks_for_root(&root).expect("second locks load");

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(
            first.root(),
            fs::canonicalize(&root).expect("root canonicalizes")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn locks_for_root_canonicalizes_symlink_roots() {
        let root = temp_root("symlink");
        let target = root.join("target");
        let link = root.join("link");
        fs::create_dir_all(&target).expect("target creates");
        std::os::unix::fs::symlink(&target, &link).expect("symlink creates");

        let target_locks = locks_for_root(&target).expect("target locks load");
        let link_locks = locks_for_root(&link).expect("link locks load");

        assert!(Arc::ptr_eq(&target_locks, &link_locks));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lock_reports_poisoned_slot() {
        let root = temp_root("poison");
        fs::create_dir_all(&root).expect("root creates");
        let locks = locks_for_root(&root).expect("locks load");
        let poison_locks = Arc::clone(&locks);
        let thread = std::thread::spawn(move || {
            let _guard = poison_locks
                .lock(CacheRootLockSlot::NodeTraces)
                .expect("slot locks");
            panic!("poison node trace lock");
        });
        assert!(thread.join().is_err());

        let error = locks
            .lock(CacheRootLockSlot::NodeTraces)
            .expect_err("slot is poisoned");

        assert!(matches!(
            error,
            CacheRootLockError::Poisoned {
                slot: CacheRootLockSlot::NodeTraces
            }
        ));

        let _ = fs::remove_dir_all(root);
    }
}
