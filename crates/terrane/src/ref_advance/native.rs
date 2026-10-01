//! Borrows existing platform bindings during sealed native ref publication.
//!
//! These adapters forward the actual captured clock and filesystem. They neither
//! establish authority nor select another platform I/O implementation.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::CommitTiming;
use crate::bucket::BucketBinding;
use crate::guard::{AdmittedCommit, HistoryObservation, OriginalCommitContext};
use crate::store::{ByteRange, Clock, LocalFs};
use terrane_core::refs::RefLogReason;

/// Retains the exact checked candidate and its bounded publication context.
pub(crate) struct RetainedPublication {
    pub(crate) admitted: AdmittedCommit,
    pub(crate) original: OriginalCommitContext,
    pub(crate) started: Duration,
    pub(crate) reason: RefLogReason,
    pub(crate) timing: CommitTiming,
}

/// Retains an actually admitted tag source and its exact create-once destination.
pub(crate) struct NativeTagRequest {
    pub(crate) source: String,
    pub(crate) target: String,
    pub(crate) token: Vec<u8>,
    pub(crate) surface: String,
    pub(crate) publication: crate::guard::TagPublication,
    pub(crate) started: Duration,
    pub(crate) timing: CommitTiming,
}

/// Borrows synchronization and independently retained original evidence.
#[derive(Clone, Copy, Default)]
pub(crate) struct PublicationObservation<'a> {
    pub(crate) history: HistoryObservation<'a>,
    pub(crate) original: Option<&'a OriginalCommitContext>,
}

/// Borrows the registered clock with native Send synchronization bounds.
#[cfg(feature = "send")]
pub(crate) type PublicationClock<'a> = dyn Clock + Sync + 'a;
/// Borrows the registered clock without imposing native Send bounds.
#[cfg(not(feature = "send"))]
pub(crate) type PublicationClock<'a> = dyn Clock + 'a;

// Both aliases refer to existing public traits. Public methods therefore do
// not expose a private marker interface or add another platform contract.
#[cfg(not(feature = "send"))]
pub(crate) use crate::store::Clock as PublicationBinding;
#[cfg(feature = "send")]
pub(crate) use std::marker::Sync as PublicationBinding;

/// Forwards required filesystem calls to the captured backend's actual binding.
pub(crate) struct FsRef<'a, F>(pub(crate) &'a F);

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<F: LocalFs + BucketBinding> LocalFs for FsRef<'_, F> {
    type Lock = F::Lock;

    async fn initialize_publication(
        &self,
        request: crate::store::NativePublicationInitialization,
    ) -> Result<crate::store::NativePublicationInitializationOutcome, crate::store::StoreFailure>
    {
        self.0.initialize_publication(request).await
    }

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> std::io::Result<crate::store::NativeExclusion> {
        self.0.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: crate::store::NativeFsEffect,
    ) -> Result<(), crate::store::NativeEffectFailure> {
        self.0.execute_retained_effect(effect).await
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        self.0.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.0.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.0.lock_existing_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.0.read(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.0.read_nofollow(path).await
    }

    async fn read_protected_record(
        &self,
        read: crate::store::NativeProtectedRead,
    ) -> Result<Option<crate::store::NativeProtectedRecord>, crate::store::StoreFailure> {
        self.0.read_protected_record(read).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        self.0.read_range(path, range).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.0.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.0.create_dir_all(path).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        self.0.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        self.0.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        self.0.symlink_metadata(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        self.0.symlink_metadata_batch(paths).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.0.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.0.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        self.0.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        self.0.sync_directory(path).await
    }
}

#[cfg(test)]
use super::PhaseTrace;

#[cfg(test)]
impl<S: crate::store::Store, C: Clock, F: LocalFs> super::Coordinator<S, C, F> {
    /// Starts a test-only phase observation using the existing injected clock.
    ///
    /// # Panics
    /// Panics if enabled diagnostics cannot write to standard error.
    pub(crate) fn phase_trace(
        &self,
        reference: &str,
        candidate: Option<terrane_core::identity::Digest>,
        started: Duration,
        phase: &str,
    ) -> PhaseTrace<'_, C> {
        PhaseTrace::new(
            self.guard().clock(),
            reference,
            candidate,
            Some(started),
            phase,
        )
    }
}
