//! Owned GC exclusion for a publication session and its lazy page readers.

use std::sync::Arc;

use crate::content_store::{ContentId, MutableRefBackend, ObjectKind, RefPublicationGuard};

use super::{RamRetention, RamRootLease, RamStoreError};

/// Selects the authoritative ref namespace for RAM publication and page readers.
///
/// The factory owns the namespace without holding a publication fence. Each
/// operation acquires a fresh fence, and its root leases may outlive the
/// factory. The selected namespace must be the one used by the graph's GC.
#[derive(Clone)]
pub struct RamRetentionAuthority {
    refs: Arc<dyn MutableRefBackend>,
}

impl RamRetentionAuthority {
    /// Selects the ref namespace used by the owning storage graph.
    #[must_use]
    pub fn new(refs: Arc<dyn MutableRefBackend>) -> Self {
        Self { refs }
    }

    /// Excludes destructive GC for a RAM publication or authenticated read.
    ///
    /// # Errors
    ///
    /// Returns an error when the selected backend cannot acquire its fence.
    pub fn acquire(&self) -> Result<FencedRamRetention, RamStoreError> {
        FencedRamRetention::acquire(self.refs.as_ref())
    }
}

/// Keeps destructive ref inventory excluded while a RAM operation is live.
///
/// Root leases share the actual backend publication fence. Closing the
/// publication session does not release exclusion while any page reader or
/// fork still retains a root lease. The backend must be the authoritative ref
/// namespace used by the storage graph's GC coordinator.
pub struct FencedRamRetention {
    fence: Arc<dyn RefPublicationGuard>,
}

impl FencedRamRetention {
    /// Acquires owned GC exclusion from the selected authoritative namespace.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot acquire publication authority.
    pub fn acquire(refs: &dyn MutableRefBackend) -> Result<Self, RamStoreError> {
        Ok(Self {
            fence: Arc::from(refs.acquire_publication_guard()?),
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
        Ok(Arc::new(FencedRootLease {
            root,
            _fence: Arc::clone(&self.fence),
        }))
    }
}

struct FencedRootLease {
    root: ContentId,
    _fence: Arc<dyn RefPublicationGuard>,
}

impl RamRootLease for FencedRootLease {
    fn root(&self) -> ContentId {
        self.root
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture ownership failures must abort the test.
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::content_store::{MemoryRefBackend, RefStoreAdmin};
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn forked_page_readers_keep_gc_excluded_after_publication_closes() {
        let refs = Arc::new(MemoryRefBackend::new());
        let authority = RamRetentionAuthority::new(refs.clone());
        let publication = authority.acquire().expect("publication authority");
        let id = ContentId::for_bytes(ObjectKind::ExactManifest, 1, b"retained root");
        let source = publication.retain_root(id).expect("source lease");
        let child = Arc::clone(&source);
        drop(publication);
        drop(authority);

        let inventory_refs = refs.clone();
        let (started, waiting) = mpsc::channel();
        let (acquired, result) = mpsc::channel();
        let inventory = std::thread::spawn(move || {
            started.send(()).expect("inventory started");
            let _fence = inventory_refs
                .acquire_ref_inventory_fence()
                .expect("exclusive inventory");
            acquired.send(()).expect("inventory acquired");
        });
        waiting.recv().expect("inventory waiting");

        assert!(result.recv_timeout(Duration::from_millis(20)).is_err());
        drop(source);
        assert!(result.recv_timeout(Duration::from_millis(20)).is_err());
        assert_eq!(child.root(), id);
        drop(child);

        result
            .recv_timeout(Duration::from_secs(2))
            .expect("final reader releases GC");
        inventory.join().expect("inventory joined");
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
