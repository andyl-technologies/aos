//! Durable per-root reader claims and short publication exclusion.
//!
//! While a publication session excludes GC inventory, a completed RAM root gets
//! an authoritative `ram-readers/<unique-owner-token>` reference. Lazy readers
//! share that exact claim through `Arc`; they hold no namespace-wide fence.
//! Last-owner retirement removes only the expected binding. Failed retirement
//! or process death leaves conservative durable ownership for reconciliation.
//! Crash retention follows the selected ref backend's durability contract;
//! an explicitly ephemeral backend provides only in-process ownership.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use crate::content_store::{
    ContentId, MutableRefBackend, ObjectKind, RefCasOutcome, RefName, RefPublicationGuard,
    StoreError,
};

use super::{RamRetention, RamRootLease, RamStoreError};

/// Selects the authoritative ref namespace for RAM publication and page readers.
#[derive(Clone)]
pub struct RamRetentionAuthority {
    refs: Arc<dyn MutableRefBackend>,
}

impl RamRetentionAuthority {
    /// Selects the same ref namespace used by the owning storage graph's GC.
    ///
    /// Reader claims inherit this backend's declared durability. An ephemeral
    /// ref namespace cannot provide retention across process death.
    #[must_use]
    pub fn new(refs: Arc<dyn MutableRefBackend>) -> Self {
        Self { refs }
    }

    /// Acquires short publication exclusion for children and reader claim creation.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected backend cannot acquire its fence.
    pub fn acquire(&self) -> Result<FencedRamRetention, RamStoreError> {
        FencedRamRetention::acquire(Arc::clone(&self.refs))
    }
}

/// Excludes destructive GC only for one bounded RAM publication operation.
///
/// Lazy root leases install durable authoritative claims while this fence is
/// held, then retain only those claims. Closing the publication session permits
/// unrelated campaign GC even while restored readers and fork clones remain.
pub struct FencedRamRetention {
    refs: Arc<dyn MutableRefBackend>,
    _fence: Box<dyn RefPublicationGuard>,
}

impl FencedRamRetention {
    /// Acquires owned publication exclusion from the selected ref authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot acquire publication authority.
    pub fn acquire(refs: Arc<dyn MutableRefBackend>) -> Result<Self, RamStoreError> {
        let fence = refs.acquire_publication_guard()?;
        Ok(Self {
            refs,
            _fence: fence,
        })
    }
}

impl RamRetention for FencedRamRetention {
    fn retain_object(&self, id: ContentId) -> Result<(), RamStoreError> {
        if id.schema_version() != 1
            || !matches!(
                id.kind(),
                ObjectKind::RamExtent | ObjectKind::RamTree | ObjectKind::ExactManifest
            )
        {
            return Err(RamStoreError::Retention(
                "unexpected RAM object identity".into(),
            ));
        }
        Ok(())
    }

    fn retain_root(&self, root: ContentId) -> Result<Arc<dyn RamRootLease>, RamStoreError> {
        if root.kind() != ObjectKind::ExactManifest || root.schema_version() != 1 {
            return Err(RamStoreError::Retention(
                "unexpected RAM root identity".into(),
            ));
        }
        // Host-only ownership names never enter a logical RAM digest or guest
        // observation. A collided name is never adopted as this reader's claim.
        for _ in 0..4 {
            let claim = unique_reader_claim()?;
            match self.refs.compare_exchange(&claim, None, root)? {
                RefCasOutcome::Advanced { next } if next == root => {
                    return Ok(Arc::new(ClaimedRootLease {
                        root,
                        claim,
                        refs: Arc::clone(&self.refs),
                    }));
                }
                RefCasOutcome::Conflict { .. } => continue,
                _ => {
                    return Err(RamStoreError::Retention(
                        "reader claim receipt mismatched".into(),
                    ));
                }
            }
        }
        Err(RamStoreError::Retention(
            "reader claim ownership collision".into(),
        ))
    }
}

struct ClaimedRootLease {
    root: ContentId,
    claim: RefName,
    refs: Arc<dyn MutableRefBackend>,
}

impl RamRootLease for ClaimedRootLease {
    fn root(&self) -> ContentId {
        self.root
    }
}

impl Drop for ClaimedRootLease {
    fn drop(&mut self) {
        // Failure, absence, or a changed target never authorizes broader cleanup.
        // An unretired durable claim remains a GC root after this owner closes.
        let _ = self.refs.compare_remove(&self.claim, self.root);
    }
}

fn unique_reader_claim() -> Result<RefName, StoreError> {
    let path = Path::new("/dev/urandom");
    let mut nonce = [0_u8; 32];
    File::open(path)
        .and_then(|mut file| file.read_exact(&mut nonce))
        .map_err(|source| StoreError::Io {
            operation: "read-RAM-reader-ownership-token",
            path: path.to_path_buf(),
            source,
        })?;
    RefName::new(format!("ram-readers/{}", blake3::hash(&nonce).to_hex()))
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture ownership failures must abort the test.
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::content_store::{
        DirectoryRefBackend, MemoryRefBackend, RefBackendCapabilities, RefInventoryRecord,
        RefRemoveOutcome, RefScanPage, RefStoreAdmin,
    };

    fn claims(refs: &dyn RefStoreAdmin) -> Vec<RefInventoryRecord> {
        let mut inventory = refs
            .acquire_ref_inventory_fence()
            .expect("exclusive inventory");
        let mut records = Vec::new();
        inventory
            .visit_refs(&mut |record| {
                records.push(record);
                Ok(())
            })
            .expect("authoritative reader claims");
        records
    }

    #[test]
    fn forked_page_readers_retain_only_their_root_and_allow_unrelated_gc() {
        let refs = Arc::new(MemoryRefBackend::new());
        let authority = RamRetentionAuthority::new(refs.clone());
        let publication = authority.acquire().expect("publication authority");
        let id = ContentId::for_bytes(ObjectKind::ExactManifest, 1, b"retained root");
        let source = publication.retain_root(id).expect("source lease");
        let child = Arc::clone(&source);
        drop(publication);
        drop(authority);

        let records = claims(refs.as_ref());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target(), id);
        assert!(records[0].name().as_str().starts_with("ram-readers/"));
        drop(source);
        assert_eq!(child.root(), id);
        assert_eq!(claims(refs.as_ref()).len(), 1);
        drop(child);
        assert!(claims(refs.as_ref()).is_empty());
    }

    #[test]
    fn independent_reader_claims_survive_restart_and_retire_without_lockfile_growth() {
        let directory = tempfile::tempdir().expect("reader directory");
        let refs = Arc::new(DirectoryRefBackend::new(directory.path()));
        let authority = RamRetentionAuthority::new(refs.clone());
        let session = authority.acquire().expect("publication");
        let id = ContentId::for_bytes(ObjectKind::ExactManifest, 1, b"durable root");
        let first = session.retain_root(id).expect("first claim");
        let second = session.retain_root(id).expect("second claim");
        drop(session);
        let reopened = DirectoryRefBackend::new(directory.path());
        let records = claims(&reopened);
        assert_eq!(records.len(), 2);
        assert_ne!(records[0].name(), records[1].name());
        assert!(records.iter().all(|record| record.target() == id));
        drop(first);
        assert_eq!(claims(&reopened).len(), 1);
        drop(second);
        assert!(claims(&reopened).is_empty());
        assert!(!directory.path().join("locks").exists());
    }

    #[test]
    fn reader_retirement_during_publication_does_not_wait_on_its_own_fence() {
        let directory = tempfile::tempdir().expect("reader directory");
        let refs = Arc::new(DirectoryRefBackend::new(directory.path()));
        let authority = RamRetentionAuthority::new(refs.clone());
        let publication = authority.acquire().expect("publication");
        let root = ContentId::for_bytes(ObjectKind::ExactManifest, 1, b"abandoned candidate");
        let candidate = publication.retain_root(root).expect("candidate claim");

        drop(candidate);
        drop(publication);

        assert!(claims(refs.as_ref()).is_empty());
    }

    #[test]
    fn reader_retirement_preserves_a_changed_authoritative_binding() {
        let directory = tempfile::tempdir().expect("reader directory");
        let refs = Arc::new(DirectoryRefBackend::new(directory.path()));
        let authority = RamRetentionAuthority::new(refs.clone());
        let publication = authority.acquire().expect("publication");
        let root = ContentId::for_bytes(ObjectKind::ExactManifest, 1, b"owned root");
        let replacement = ContentId::for_bytes(ObjectKind::ExactManifest, 1, b"other owner");
        let reader = publication.retain_root(root).expect("reader claim");
        drop(publication);
        let claim = claims(refs.as_ref()).remove(0);
        assert!(matches!(
            refs.compare_exchange(claim.name(), Some(root), replacement)
                .expect("replace binding"),
            RefCasOutcome::Advanced { next } if next == replacement
        ));

        drop(reader);

        assert_eq!(
            refs.read_ref(claim.name()).expect("preserved binding"),
            Some(replacement)
        );
    }

    struct FailedRetirement {
        inner: DirectoryRefBackend,
    }

    impl MutableRefBackend for FailedRetirement {
        fn capabilities(&self) -> RefBackendCapabilities {
            self.inner.capabilities()
        }
        fn acquire_publication_guard(&self) -> Result<Box<dyn RefPublicationGuard>, StoreError> {
            self.inner.acquire_publication_guard()
        }
        fn read_ref(&self, name: &RefName) -> Result<Option<ContentId>, StoreError> {
            self.inner.read_ref(name)
        }
        fn scan_refs(
            &self,
            namespace: &RefName,
            after: Option<&RefName>,
            limit: usize,
        ) -> Result<RefScanPage, StoreError> {
            self.inner.scan_refs(namespace, after, limit)
        }
        fn compare_exchange(
            &self,
            name: &RefName,
            expected: Option<ContentId>,
            next: ContentId,
        ) -> Result<RefCasOutcome, StoreError> {
            self.inner.compare_exchange(name, expected, next)
        }
        fn compare_remove(
            &self,
            _: &RefName,
            _: ContentId,
        ) -> Result<RefRemoveOutcome, StoreError> {
            Err(StoreError::Unavailable)
        }
    }

    #[test]
    fn failed_reader_retirement_leaves_conservative_durable_ownership() {
        let directory = tempfile::tempdir().expect("reader directory");
        let backend = Arc::new(FailedRetirement {
            inner: DirectoryRefBackend::new(directory.path()),
        });
        let authority = RamRetentionAuthority::new(backend);
        let session = authority.acquire().expect("publication");
        let id = ContentId::for_bytes(ObjectKind::ExactManifest, 1, b"failed owner cleanup");
        let owner = session.retain_root(id).expect("owned root");
        drop(session);
        drop(owner);
        drop(authority);

        let reopened = DirectoryRefBackend::new(directory.path());
        let records = claims(&reopened);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].target(), id);
        assert_eq!(
            reopened
                .compare_remove(records[0].name(), id)
                .expect("proven closed owner cleanup"),
            RefRemoveOutcome::Removed
        );
        assert_eq!(
            reopened
                .compare_remove(records[0].name(), id)
                .expect("idempotent cleanup"),
            RefRemoveOutcome::AlreadyAbsent
        );
    }

    #[test]
    fn retention_rejects_other_object_kinds_and_root_editions() {
        let authority = RamRetentionAuthority::new(Arc::new(MemoryRefBackend::new()));
        let publication = authority.acquire().expect("publication authority");
        let wrong_kind = ContentId::for_bytes(ObjectKind::RamExtent, 1, b"page");
        let wrong_edition = ContentId::for_bytes(ObjectKind::ExactManifest, 2, b"root");

        assert!(publication.retain_root(wrong_kind).is_err());
        assert!(publication.retain_root(wrong_edition).is_err());
        assert!(publication.retain_object(wrong_edition).is_err());
    }
}
