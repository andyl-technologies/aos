//! Withholds the actual routed lower read while the guest observes worker progress.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use terrane_format::identity::{Identity, IdentityKind};
use terrane_sdk::store::{
    ByteRange, Capabilities, CapabilityReport, ContentStore, ContentUpload, IdentityPrefix,
    StoreErrorKind, StoreFailure,
};
use tokio::sync::Notify;

/// Retains the original lower store and one guest-controlled content-read pause.
pub(super) struct PausedLower<S> {
    /// Original routed lower store used for every actual read.
    pub(super) original: S,
    /// Number of actual chunk reads submitted to the lower store.
    pub(super) reads: Arc<AtomicUsize>,
    /// Signals acceptance of an original cold content read.
    pub(super) started: Arc<Notify>,
    /// Releases that same accepted read after the guest observes its waiters.
    pub(super) resume: Arc<Notify>,
}

impl<S: CapabilityReport> CapabilityReport for PausedLower<S> {
    fn capabilities(&self) -> &Capabilities {
        self.original.capabilities()
    }
}

#[async_trait::async_trait]
impl<S: ContentStore + Send + Sync> ContentStore for PausedLower<S> {
    async fn put(&self, _: ContentUpload<'_>) -> std::result::Result<Identity, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> std::result::Result<Vec<u8>, StoreFailure> {
        if identity.kind() == IdentityKind::Chunk {
            self.reads.fetch_add(1, Ordering::Relaxed);
            self.started.notify_one();
            self.resume.notified().await;
        }
        self.original.get(identity, range).await
    }

    async fn has(&self, identities: &[Identity]) -> std::result::Result<Vec<bool>, StoreFailure> {
        self.original.has(identities).await
    }

    async fn list(
        &self,
        prefix: &IdentityPrefix,
    ) -> std::result::Result<Vec<Identity>, StoreFailure> {
        self.original.list(prefix).await
    }
}
