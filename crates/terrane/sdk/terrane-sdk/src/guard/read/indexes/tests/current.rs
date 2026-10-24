//! Observes and pauses actual scalar native reads without substituting authority.

use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

use crate::store::{ByteRange, LocalFs, TokioFileLock, TokioLocalFs};

/// Delegates real native initialization, exclusion, execution and file operations.
#[derive(Clone, Default)]
pub(super) struct ObservedFs {
    trace: Arc<Mutex<Vec<PathBuf>>>,
    hook: Arc<Mutex<Option<Hook>>>,
    /// Counts actual retained effect submissions for read-only transition assertions.
    pub(super) effects: Arc<AtomicUsize>,
}

struct Hook {
    path: PathBuf,
    remaining: usize,
    handoff: Handoff,
}

/// Signals one exact actual read and holds only the asynchronous caller at that boundary.
///
/// This is not native descriptor or retention evidence; cancellation drops the
/// caller and cannot produce a result. The same native operations still perform
/// all existing path, metadata, body and executor checks after release.
#[derive(Clone)]
pub(super) struct Handoff {
    /// Actual hit counter; every registered hook must be consumed exactly once.
    pub(super) hits: Arc<AtomicUsize>,
    reached: Arc<tokio::sync::Notify>,
    released: Arc<tokio::sync::Notify>,
}

impl Handoff {
    /// Waits for the actual selected read without modifying existing fixture deadlines.
    ///
    /// # Errors
    /// Returns the unchanged ten-second handoff timeout when the exact hook does not fire.
    pub(super) async fn wait(&self) -> Result<(), tokio::time::error::Elapsed> {
        tokio::time::timeout(std::time::Duration::from_secs(10), self.reached.notified()).await
    }

    /// Releases only the signaled asynchronous test caller.
    pub(super) fn release(&self) {
        self.released.notify_one();
    }
}

impl ObservedFs {
    /// Records exact original read names for independent final-frontier calibration.
    ///
    /// # Panics
    /// Panics if another fixture task poisoned the trace lock.
    pub(super) fn trace(&self) -> Vec<PathBuf> {
        match self.trace.lock() {
            Ok(trace) => trace.clone(),
            Err(_) => panic!("native read fixture trace poisoned"),
        }
    }

    /// Clears only ordinary diagnostic names, without changing read behavior or trust.
    ///
    /// # Panics
    /// Panics if another fixture task poisoned the trace lock.
    pub(super) fn clear_trace(&self) {
        match self.trace.lock() {
            Ok(mut trace) => trace.clear(),
            Err(_) => panic!("native read fixture trace poisoned"),
        }
    }

    /// Pauses the specified ordinal of an actual original read in the next lookup.
    ///
    /// # Panics
    /// Panics for zero ordinal, an outstanding hook or a poisoned fixture lock.
    pub(super) fn pause(&self, path: PathBuf, ordinal: usize) -> Handoff {
        assert!(ordinal > 0);
        let handoff = Handoff {
            hits: Arc::new(AtomicUsize::new(0)),
            reached: Arc::new(tokio::sync::Notify::new()),
            released: Arc::new(tokio::sync::Notify::new()),
        };
        let mut hook = match self.hook.lock() {
            Ok(hook) => hook,
            Err(_) => panic!("native read fixture hook poisoned"),
        };
        assert!(hook.is_none(), "unconsumed native read fixture hook");
        *hook = Some(Hook {
            path,
            remaining: ordinal,
            handoff: handoff.clone(),
        });
        handoff
    }

    fn observe(&self, path: &Path) -> std::io::Result<()> {
        self.trace
            .lock()
            .map_err(|_| std::io::Error::other("native read trace poisoned"))?
            .push(path.to_owned());
        Ok(())
    }

    async fn before_read(&self, path: &Path) -> std::io::Result<()> {
        self.observe(path)?;
        let selected = {
            let mut hook = self
                .hook
                .lock()
                .map_err(|_| std::io::Error::other("native read hook poisoned"))?;
            if let Some(selected) = hook.as_mut() {
                if selected.path == path {
                    selected.remaining -= 1;
                    if selected.remaining == 0 {
                        hook.take().map(|hook| hook.handoff)
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        };
        if let Some(handoff) = selected {
            handoff.hits.fetch_add(1, Ordering::SeqCst);
            handoff.reached.notify_one();
            handoff.released.notified().await;
        }
        Ok(())
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for ObservedFs {
    type Lock = TokioFileLock;

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> std::io::Result<crate::store::NativeExclusion> {
        TokioLocalFs.retain_native_exclusion(held)
    }

    async fn initialize_publication(
        &self,
        request: crate::store::NativePublicationInitialization,
    ) -> Result<crate::store::NativePublicationInitializationOutcome, crate::store::StoreFailure>
    {
        TokioLocalFs.initialize_publication(request).await
    }

    async fn execute_retained_effect(
        &self,
        effect: crate::store::NativeFsEffect,
    ) -> Result<(), crate::store::NativeEffectFailure> {
        self.effects.fetch_add(1, Ordering::SeqCst);
        TokioLocalFs.execute_retained_effect(effect).await
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        TokioLocalFs.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.lock_existing_exclusive(path).await
    }

    async fn try_lock_existing_shared(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_shared(path).await
    }

    async fn try_lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        TokioLocalFs.try_lock_existing_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.observe(path)?;
        TokioLocalFs.read(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.before_read(path).await?;
        TokioLocalFs.read_nofollow(path).await
    }

    async fn read_ordinary_record(
        &self,
        read: crate::store::NativeOrdinaryRead,
    ) -> std::io::Result<Option<crate::store::NativeOrdinaryRecord>> {
        // Leaf reads keep the scalar observation and pause boundaries above.
        // Candidate history still requires the genuine native closing recipe.
        if read.path_for_test().is_some() {
            return Ok(None);
        }

        TokioLocalFs.read_ordinary_record(read).await
    }

    async fn read_payload_ranges(
        &self,
        read: crate::store::NativePayloadRangeRead,
    ) -> std::io::Result<Option<crate::store::NativePayloadRangeRecord>> {
        if let Some((path, _)) = read.read_data_range() {
            self.observe(path)?;
        }
        // Current snapshot history requires the original native descriptors
        // and physical closing recipe from this same filesystem binding.
        TokioLocalFs.read_payload_ranges(read).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        self.observe(path)?;
        TokioLocalFs.read_range(path, range).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.observe(path)?;
        TokioLocalFs.write_new(path, bytes).await?;
        Ok(())
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.create_dir_all(path).await
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.create_dir_new(path).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        TokioLocalFs.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.symlink_metadata(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        TokioLocalFs.symlink_metadata_batch(paths).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.remove_file(path).await
    }

    async fn remove_dir(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.remove_dir(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        TokioLocalFs.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_file(path).await
    }

    async fn sync_file_nofollow(
        &self,
        path: &Path,
        expected: &std::fs::Metadata,
    ) -> std::io::Result<std::fs::Metadata> {
        TokioLocalFs.sync_file_nofollow(path, expected).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        TokioLocalFs.sync_directory(path).await
    }

    async fn set_permissions(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        TokioLocalFs.set_permissions(path, permissions).await
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        TokioLocalFs
            .set_permissions_and_sync(path, permissions)
            .await
    }

    async fn read_link(&self, path: &Path) -> std::io::Result<PathBuf> {
        TokioLocalFs.read_link(path).await
    }

    async fn list_xattrs(&self, path: &Path) -> std::io::Result<Vec<std::ffi::OsString>> {
        TokioLocalFs.list_xattrs(path).await
    }

    async fn get_xattr(
        &self,
        path: &Path,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<Option<Vec<u8>>> {
        TokioLocalFs.get_xattr(path, name).await
    }
}

/// Exercises independent actual producer/current and trust decisions without replacing history.
///
/// # Errors
/// Preserves genuine factory, signed policy transition and actual verification failures.
/// # Panics
/// Panics for wrong current/trust results, counters or shared fixture assertions.
pub(super) async fn current_contexts() -> super::support::TestResult {
    use super::super::{IndexLookupCurrentWork, authorization, loading};
    use super::support::{ATTRIBUTE, Fixture, publish, publish_policy, snapshot, value};
    use crate::guard::HistoryObservation;
    use crate::store::{RefStore, StoreErrorKind};
    use terrane_format::provenance::{Preset, Selector};

    let fixture = Fixture::new().await?;
    let published = publish(&fixture.repository, &[b"file"], &[], true, true).await?;
    let guard = fixture.repository.coordinator().guard();
    let evidence = crate::guard::TreeEvidence::load_commit(
        guard.store(),
        published.record.commit,
        guard.config().min_chunk_size,
    )
    .await?;
    let commit = evidence.commit.as_ref().ok_or("published Commit absent")?;
    assert!(
        commit.profile_pair.required_properties.is_some(),
        "actual published view lacks its signed requirement snapshot"
    );
    let (semantics, inputs) = guard
        .selected_view_context_for_tests(published.record.commit, evidence.root)
        .unwrap_or_else(|error| panic!("published view selection failed: {error:?}"));
    assert_eq!(
        semantics,
        terrane_format::properties::selected::Selection::Recorded(
            fixture.authoring.context().clone()
        )
    );
    assert_eq!(&inputs, fixture.authoring.registries());

    let selected = snapshot(&fixture.repository)
        .await
        .unwrap_or_else(|error| panic!("first current snapshot failed: {error:?}"));
    let (_, profile) = guard
        .selected_view_profile(&selected.commit, HistoryObservation::default())
        .unwrap_or_else(|error| panic!("first current profile failed: {error:?}"));
    let rows = loading::discover(
        guard.store(),
        &selected,
        ATTRIBUTE,
        &value()?,
        &profile,
        262144,
        false,
    )
    .await
    .unwrap_or_else(|error| panic!("first current index discovery failed: {error:?}"));
    assert_eq!(rows.present.len(), 1);
    let row = &rows.present[0];
    let mut requests = Vec::new();
    let mut work = IndexLookupCurrentWork::default();
    assert!(
        authorization::check_producer(
            guard,
            &selected,
            row,
            ATTRIBUTE,
            HistoryObservation::default(),
            &mut requests,
            &mut work
        )
        .await
        .unwrap_or_else(|error| panic!("initial attribute producer check failed: {error:?}"))
        .is_some()
    );
    assert!(work.producer_checks > 0);
    assert!(!requests.is_empty());

    // A supported actual current-policy transition revokes Read without changing
    // the immutable old producer view, its signed inline value or original scope.
    let head = publish_policy(&fixture.repository, &[b"file"], &[], true, true, None, None).await?;
    let mut requests = Vec::new();
    let mut work = IndexLookupCurrentWork::default();
    assert!(
        authorization::check_producer(
            guard,
            &selected,
            row,
            ATTRIBUTE,
            HistoryObservation::default(),
            &mut requests,
            &mut work
        )
        .await?
        .is_none()
    );
    assert!(work.producer_checks > 0);
    assert!(requests.is_empty());
    match guard.lookup_index(&selected, ATTRIBUTE, &value()?).await {
        Err(super::super::IndexLookupError::Store(failure)) => {
            assert!(matches!(failure.kind(), StoreErrorKind::Denied { .. }))
        }
        other => panic!("current Read revocation did not preserve typed denial: {other:?}"),
    }
    assert_eq!(
        guard.store().ref_get(super::support::REFERENCE).await?,
        Some(head.record)
    );

    let untrusted = Fixture::new().await?;
    let selector = Selector::preset(Preset::Attested);
    publish_policy(
        &untrusted.repository,
        &[b"file"],
        &[],
        true,
        true,
        Some(31),
        Some(selector.encode()),
    )
    .await?;
    let selected = snapshot(&untrusted.repository).await?;
    let result = untrusted
        .repository
        .coordinator()
        .guard()
        .lookup_index(&selected, ATTRIBUTE, &value()?)
        .await?;
    assert_eq!(result.work.candidates.candidates, 1);
    assert_eq!(result.work.current.occurrence_checks, 1);
    assert_eq!(result.work.current.attribute_origin_checks, 0);
    assert!(result.objects.is_empty());
    assert!(result.is_complete());
    Ok(())
}

/// Injects an exact immutable input failure into real native loader work only.
struct UnavailableIndex<'a, S> {
    actual: &'a S,
    node: terrane_format::identity::Identity,
}

impl<S: crate::store::CapabilityReport> crate::store::CapabilityReport for UnavailableIndex<'_, S> {
    fn capabilities(&self) -> &crate::store::Capabilities {
        self.actual.capabilities()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl<S: crate::store::ContentStore + Sync> crate::store::ContentStore for UnavailableIndex<'_, S> {
    async fn put(
        &self,
        _: crate::store::ContentUpload<'_>,
    ) -> Result<terrane_format::identity::Identity, crate::store::StoreFailure> {
        Err(crate::store::StoreFailure::new(
            crate::store::StoreErrorKind::ReadOnly,
        ))
    }

    async fn get(
        &self,
        identity: &terrane_format::identity::Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, crate::store::StoreFailure> {
        if *identity == self.node {
            return Err(crate::store::StoreFailure::with_source(
                crate::store::StoreErrorKind::Unavailable { retry_after: None },
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "finite unavailable immutable Index input",
                ),
            ));
        }
        self.actual.get(identity, range).await
    }

    async fn has(
        &self,
        identities: &[terrane_format::identity::Identity],
    ) -> Result<Vec<bool>, crate::store::StoreFailure> {
        self.actual.has(identities).await
    }

    async fn list(
        &self,
        prefix: &crate::store::IdentityPrefix,
    ) -> Result<Vec<terrane_format::identity::Identity>, crate::store::StoreFailure> {
        self.actual.list(prefix).await
    }
}

/// Proves unavailable bound inputs cannot select the MissingBinding-only walk branch.
///
/// # Errors
/// Preserves genuine native fixture, publication and independently selected profile failures.
/// # Panics
/// Panics if a scoped loader failure loses its exact subject/cause or selects fallback.
pub(super) async fn bound_failure_never_walks() -> super::support::TestResult {
    use super::super::{IndexLookupError, loading};
    use super::support::{ATTRIBUTE, Fixture, expected, publish, snapshot, value};
    use crate::guard::HistoryObservation;
    use crate::store::StoreErrorKind;
    use std::error::Error as _;
    use terrane_format::identity::{IdentityKind, TERRANE_V1};

    let fixture = Fixture::new().await?;
    publish(&fixture.repository, &[b"file"], &[], true, true).await?;
    let selected = snapshot(&fixture.repository).await?;
    let guard = fixture.repository.coordinator().guard();
    let (_, profile) =
        guard.selected_view_profile(&selected.commit, HistoryObservation::default())?;
    let canonical = value()?;
    let (primary, _) = expected(&[b"file"], &[], &canonical)?;
    let unavailable = UnavailableIndex {
        actual: guard.store(),
        node: TERRANE_V1.from_digest(IdentityKind::Node, &primary)?,
    };
    match loading::discover(
        &unavailable,
        &selected,
        ATTRIBUTE,
        &canonical,
        &profile,
        262144,
        true,
    )
    .await
    {
        Err(IndexLookupError::Index(crate::indexing::Error::Store { node, failure })) => {
            assert_eq!(node, primary);
            assert_eq!(
                failure.kind(),
                &StoreErrorKind::Unavailable { retry_after: None }
            );
            let source = failure
                .source()
                .and_then(|source| source.downcast_ref::<std::io::Error>());
            match source {
                Some(source) => assert_eq!(source.kind(), std::io::ErrorKind::PermissionDenied),
                None => panic!("exact unavailable input cause was lost"),
            }
        }
        Err(other) => panic!("expected exact bound Node failure, got {other:?}"),
        Ok(_) => panic!("unavailable bound primary falsely selected fallback"),
    }
    Ok(())
}

/// Cancels a genuinely paused live lookup without returning data or changing selected state.
///
/// This does not assert exclusions outlive an already canceled scalar native read.
/// The pause occurs before dispatch and supplies neither a native descriptor nor authority.
///
/// # Errors
/// Preserves genuine native setup, actual read-handoff and selected-ref read failures.
/// # Panics
/// Panics if the actual hook is not consumed or lookup completes before cancellation.
pub(super) async fn cancel_without_result() -> super::support::TestResult {
    use super::support::{ATTRIBUTE, Fixture, REFERENCE, publish, snapshot, value};
    use crate::store::RefStore;

    let fixture = Fixture::new().await?;
    let head = publish(&fixture.repository, &[b"file"], &[], true, true).await?;
    let selected = snapshot(&fixture.repository).await?;
    let path = fixture.control.join("registration.cbor");
    let handoff = fixture.fs.pause(path, 1);
    let before = fixture.fs.effects.load(Ordering::SeqCst);
    let canonical = value()?;
    let guard = fixture.repository.coordinator().guard();
    let mut lookup = Box::pin(guard.lookup_index(&selected, ATTRIBUTE, &canonical));
    tokio::select! {
        result = &mut lookup => panic!("lookup completed before actual cancellation handoff: {result:?}"),
        signal = handoff.wait() => signal?,
    }
    assert_eq!(handoff.hits.load(Ordering::SeqCst), 1);
    let competing = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(fixture.control.join("retention.lock"))?;
    assert!(matches!(
        competing.try_lock(),
        Err(std::fs::TryLockError::WouldBlock)
    ));
    drop(lookup);
    handoff.release();
    assert_eq!(fixture.fs.effects.load(Ordering::SeqCst), before);
    assert_eq!(guard.store().ref_get(REFERENCE).await?, Some(head.record));
    Ok(())
}
