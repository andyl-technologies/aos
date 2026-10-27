//! Observes and pauses actual copied native requests while retaining their Frames.
//!
//! Delegation executes the production native effect unchanged. Deliberate no-op
//! and failure injections leave completion channels empty; they never construct
//! receipts, authority or elapsed-time claims.

use crate::store::native_publication_effects::collection::test_fs::TestFs;
use crate::store::{ByteRange, EffectFaultProbe, LocalFs, NativeEffectFailure, NativeFsEffect};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

// Probe descriptions expose only the actual operation kind and fixture path.
fn describe_effect(probe: EffectFaultProbe<'_>) -> String {
    match probe {
        EffectFaultProbe::SealRetirementBarrier(path) => {
            format!("SealRetirementBarrier {}", path.display())
        }
        EffectFaultProbe::SealMutationPublication(path) => {
            format!("SealMutationPublication {}", path.display())
        }
        EffectFaultProbe::SealRawPublication(path) => {
            format!("SealRawPublication {}", path.display())
        }
        EffectFaultProbe::SealLeasePublication(path) => {
            format!("SealLeasePublication {}", path.display())
        }
        EffectFaultProbe::CopiedPreparation(path) => {
            format!("CopiedPreparation {}", path.display())
        }
        EffectFaultProbe::CopiedBarrier(path) => format!("CopiedBarrier {}", path.display()),
        EffectFaultProbe::CopiedOwnership(path) => format!("CopiedOwnership {}", path.display()),
        EffectFaultProbe::PermanentLocalObservation(path) => {
            format!("PermanentLocalObservation {}", path.display())
        }
        EffectFaultProbe::PermanentLocalReclaim(path) => {
            format!("PermanentLocalReclaim {}", path.display())
        }
        EffectFaultProbe::PermanentLocalProgress(path) => {
            format!("PermanentLocalProgress {}", path.display())
        }
        EffectFaultProbe::SealPendingCreation(path) => {
            format!("SealPendingCreation {}", path.display())
        }
        EffectFaultProbe::ObserveCurrentPair(path) => {
            format!("ObserveCurrentPair {}", path.display())
        }
        EffectFaultProbe::ObserveLocalTriple(path) => {
            format!("ObserveLocalTriple {}", path.display())
        }
        EffectFaultProbe::SealArtifact(path) => format!("SealArtifact {}", path.display()),
        EffectFaultProbe::CommitCreation(path) => format!("CommitCreation {}", path.display()),
        EffectFaultProbe::WriteNew(path) => format!("WriteNew {}", path.display()),
        EffectFaultProbe::DirectorySync(path) => format!("DirectorySync {}", path.display()),
        EffectFaultProbe::RenameNoReplace(path) => format!("RenameNoReplace {}", path.display()),
        EffectFaultProbe::Rename(path) => format!("Rename {}", path.display()),
        EffectFaultProbe::LocalFirstOwnership(path, phase) => {
            format!("LocalFirstOwnership {} phase={phase}", path.display())
        }
        EffectFaultProbe::LocalDeletion(path, phase) => {
            format!("LocalDeletion {} phase={phase:?}", path.display())
        }
        EffectFaultProbe::FileSync => "FileSync".into(),
        EffectFaultProbe::Other => "Other".into(),
    }
}

/// Identifies one genuinely submitted copied phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    /// Selects preparation synchronization before NEW Trash creation.
    Preparation,
    /// Selects the real committed Trash barrier observation.
    Barrier,
    /// Selects final owner synchronization after fresh DATA qualification.
    Ownership,
}

struct QueuedLock {
    gate: tokio::sync::Mutex<()>,
    attempted: Mutex<Option<oneshot::Sender<()>>>,
}

struct Pause {
    phase: Phase,
    after: bool,
    arrived: oneshot::Sender<PathBuf>,
    release: oneshot::Receiver<()>,
}

#[derive(Default)]
struct State {
    pause: Mutex<Option<Pause>>,
    lease_completions: Mutex<Option<tokio::sync::mpsc::UnboundedSender<PathBuf>>>,
    queued_lock: Mutex<Option<Arc<QueuedLock>>>,
    noop: Mutex<Option<Phase>>,
    completed: Mutex<Vec<Phase>>,
    noop_owner_slot: std::sync::atomic::AtomicBool,
    noop_preparation_slot: std::sync::atomic::AtomicBool,
    refused_slot: Mutex<Option<PathBuf>>,
}

/// Delegates actual local storage and records genuine copied phase completions.
#[derive(Clone)]
pub(crate) struct CopiedFs {
    inner: TestFs,
    state: Arc<State>,
}

impl CopiedFs {
    /// Wraps the actual native fixture filesystem without replacing its clock.
    pub(crate) fn new(inner: TestFs) -> Self {
        Self {
            inner,
            state: Arc::new(State::default()),
        }
    }

    /// Pauses one real submitted phase before passing its retained effect onward.
    ///
    /// # Panics
    /// Panics on poisoned observation state or a second simultaneous hook.
    pub(crate) fn pause(&self, phase: Phase) -> (oneshot::Receiver<PathBuf>, oneshot::Sender<()>) {
        let (arrived, received) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let mut pending = self.state.pause.lock().unwrap();
        assert!(pending.is_none());
        *pending = Some(Pause {
            phase,
            after: false,
            arrived,
            release: released,
        });
        (received, release)
    }

    /// Pauses after actual delegation and ACK, before returning the real effect.
    ///
    /// # Panics
    /// Panics on poisoned observation state or a second simultaneous hook.
    pub(crate) fn pause_completed(
        &self,
        phase: Phase,
    ) -> (oneshot::Receiver<PathBuf>, oneshot::Sender<()>) {
        let (arrived, received) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let mut pending = self.state.pause.lock().unwrap();
        assert!(pending.is_none());
        *pending = Some(Pause {
            phase,
            after: true,
            arrived,
            release: released,
        });
        (received, release)
    }

    /// Serializes actual lock acquisitions after observing the first blocked attempt.
    ///
    /// # Panics
    /// Panics if another queued-lock observation is installed.
    pub(crate) fn observe_queued_lock(&self) -> oneshot::Receiver<()> {
        let (attempted, arrived) = oneshot::channel();
        let mut pending = self.state.queued_lock.lock().unwrap();
        assert!(pending.is_none());
        *pending = Some(Arc::new(QueuedLock {
            gate: tokio::sync::Mutex::new(()),
            attempted: Mutex::new(Some(attempted)),
        }));
        arrived
    }

    /// Closes unused phase hooks and lease observations after the real operation returns.
    ///
    /// An executing hook has already taken this state. Dropping only an unused
    /// sender reports cancellation to its observer without inventing an arrival.
    ///
    /// # Panics
    /// Panics if the fixture observation mutex is poisoned.
    pub(crate) fn close_unreached_pause(&self) {
        self.state.pause.lock().unwrap().take();
        self.state.lease_completions.lock().unwrap().take();
    }

    /// Observes genuine native lease ACKs without pausing or changing their effects.
    ///
    /// Each path names the actual selected protected slot. Tests independently
    /// reread its transaction and current whole lease beneath namespace exclusion.
    ///
    /// # Panics
    /// Panics on poisoned observation state or a second simultaneous observer.
    pub(crate) fn observe_lease_completions(
        &self,
    ) -> tokio::sync::mpsc::UnboundedReceiver<PathBuf> {
        let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
        let mut pending = self.state.lease_completions.lock().unwrap();
        assert!(pending.is_none());
        *pending = Some(sender);
        receiver
    }

    /// Leaves one genuine native request unexecuted, without populating its ACK.
    ///
    /// # Panics
    /// Panics on poisoned observation state or a second pending no-op.
    pub(crate) fn noop(&self, phase: Phase) {
        let mut pending = self.state.noop.lock().unwrap();
        assert!(pending.is_none());
        *pending = Some(phase);
    }

    /// Leaves the actual final copied owner slot rename unexecuted.
    pub(crate) fn noop_owner_slot(&self) {
        self.state
            .noop_owner_slot
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Leaves the actual proposed preparation slot rename unexecuted.
    pub(crate) fn noop_preparation_slot(&self) {
        self.state
            .noop_preparation_slot
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Returns the genuine slot path whose rename was deliberately unexecuted.
    ///
    /// # Panics
    /// Panics on poisoned observation state.
    pub(crate) fn refused_slot(&self) -> Option<PathBuf> {
        self.state.refused_slot.lock().unwrap().clone()
    }

    /// Returns only phases whose actual delegated native effect succeeded.
    ///
    /// # Panics
    /// Panics on poisoned observation state.
    pub(crate) fn completed(&self) -> Vec<Phase> {
        self.state.completed.lock().unwrap().clone()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for CopiedFs {
    type Lock = crate::store::TokioFileLock;

    async fn initialize_publication(
        &self,
        request: crate::store::NativePublicationInitialization,
    ) -> Result<crate::store::NativePublicationInitializationOutcome, crate::store::StoreFailure>
    {
        self.inner.initialize_publication(request).await
    }

    fn retain_native_exclusion(
        &self,
        held: &Self::Lock,
    ) -> std::io::Result<crate::store::NativeExclusion> {
        self.inner.retain_native_exclusion(held)
    }

    async fn execute_retained_effect(
        &self,
        effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        if (self
            .state
            .noop_owner_slot
            .load(std::sync::atomic::Ordering::SeqCst)
            || self
                .state
                .noop_preparation_slot
                .load(std::sync::atomic::Ordering::SeqCst))
            && let EffectFaultProbe::RenameNoReplace(target) = effect.fault_probe()
            && target
                .parent()
                .is_some_and(|parent| parent.ends_with("publication/commits"))
            && let Some(staged) = effect.rename_noreplace_source()
        {
            // These are actual staged protected bytes, inspected only to target
            // the native fault. Decoding them supplies no request or permission.
            let bytes = self.inner.read(staged).await?;
            let slot = terrane_format::gc::publication::PublicationCommit::decode(&bytes)
                .map_err(|_| std::io::Error::other("malformed actual staged slot"))?;
            let control = target
                .parent()
                .and_then(Path::parent)
                .and_then(Path::parent)
                .ok_or_else(|| std::io::Error::other("actual slot control missing"))?;
            let bytes = self.inner.read(&control.join(slot.transaction_key)).await?;
            let transaction =
                terrane_format::gc::publication::PublicationTransaction::decode(&bytes)
                    .map_err(|_| std::io::Error::other("malformed actual staged transaction"))?;
            if self
                .state
                .noop_preparation_slot
                .load(std::sync::atomic::Ordering::SeqCst)
                && matches!(
                    &transaction.proof,
                    terrane_format::gc::publication::PublicationProof::Raw
                )
                && transaction.changes.iter().any(|change| {
                    change.new.as_deref().is_some_and(|bytes| {
                        terrane_format::gc::retirement::CopiedRetirementPreparation::decode(bytes)
                            .is_ok_and(|preparation| {
                                preparation.plan.check_key(&change.key).is_ok()
                            })
                    })
                })
            {
                *self.state.refused_slot.lock().unwrap() = Some(target.to_owned());
                return Ok(());
            }
            if let terrane_format::gc::publication::PublicationProof::PermanentRetirement {
                authorization,
                ..
            } = transaction.proof
                && matches!(
                    terrane_format::gc::retirement::PermanentDeleteAuthorization::decode(
                        &authorization
                    )
                    .map_err(|_| std::io::Error::other("malformed actual staged authorization"))?,
                    terrane_format::gc::retirement::PermanentDeleteAuthorization::Copied(_)
                )
            {
                self.state
                    .noop_owner_slot
                    .store(false, std::sync::atomic::Ordering::SeqCst);
                *self.state.refused_slot.lock().unwrap() = Some(target.to_owned());
                return Ok(());
            }
        }
        let matched = match effect.fault_probe() {
            EffectFaultProbe::CopiedPreparation(path) => {
                Some((Phase::Preparation, path.to_owned()))
            }
            EffectFaultProbe::CopiedBarrier(path) => Some((Phase::Barrier, path.to_owned())),
            EffectFaultProbe::CopiedOwnership(path) => Some((Phase::Ownership, path.to_owned())),
            _ => None,
        };
        let lease_slot = match effect.fault_probe() {
            EffectFaultProbe::SealLeasePublication(path) => Some(path.to_owned()),
            _ => None,
        };
        if let Some((phase, path)) = &matched {
            let pause = {
                let mut pending = self.state.pause.lock().unwrap();
                if pending
                    .as_ref()
                    .is_some_and(|pause| pause.phase == *phase && !pause.after)
                {
                    pending.take()
                } else {
                    None
                }
            };
            if let Some(pause) = pause {
                pause
                    .arrived
                    .send(path.clone())
                    .map_err(|_| std::io::Error::other("copied phase observer dropped"))?;
                pause
                    .release
                    .await
                    .map_err(|_| std::io::Error::other("copied phase release dropped"))?;
            }
            let noop = {
                let mut pending = self.state.noop.lock().unwrap();
                if *pending == Some(*phase) {
                    pending.take();
                    true
                } else {
                    false
                }
            };
            if noop {
                return Ok(());
            }
        }
        if let Some((phase, _)) = &matched {
            eprintln!("copied native phase submitted: {phase:?}");
        }
        let description = describe_effect(effect.fault_probe());
        eprintln!("copied delegated effect submitted: {description}");
        let result = self.inner.execute_retained_effect(effect).await;
        eprintln!(
            "copied delegated effect returned: {description} success={}",
            result.is_ok()
        );
        result?;
        if let Some(path) = lease_slot
            && let Some(sender) = self.state.lease_completions.lock().unwrap().as_ref()
        {
            // The unchanged native executor has synchronized and acknowledged
            // this lease. The observation supplies neither a receipt nor authority.
            let _ = sender.send(path);
        }
        if let Some((phase, path)) = matched {
            eprintln!("copied native phase completed: {phase:?}");
            self.state.completed.lock().unwrap().push(phase);
            let pause = {
                let mut pending = self.state.pause.lock().unwrap();
                if pending
                    .as_ref()
                    .is_some_and(|pause| pause.phase == phase && pause.after)
                {
                    pending.take()
                } else {
                    None
                }
            };
            if let Some(pause) = pause {
                pause
                    .arrived
                    .send(path)
                    .map_err(|_| std::io::Error::other("copied completion observer dropped"))?;
                pause
                    .release
                    .await
                    .map_err(|_| std::io::Error::other("copied completion release dropped"))?;
            }
        }
        Ok(())
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        self.inner.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.inner.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        eprintln!("copied existing lock attempt: {}", path.display());
        let queued = self.state.queued_lock.lock().unwrap().clone();
        let Some(queued) = queued else {
            let result = self.inner.lock_existing_exclusive(path).await;
            eprintln!(
                "copied existing lock returned: {} success={}",
                path.display(),
                result.is_ok()
            );
            return result;
        };
        // Serialize contenders until the first actual filesystem lock is held.
        // This imposes no assumption about the underlying lock's FIFO behavior.
        let _gate = queued.gate.lock().await;
        let mut acquisition = std::pin::pin!(self.inner.lock_existing_exclusive(path));
        let attempted = queued.attempted.lock().unwrap().take();
        if let Some(attempted) = attempted {
            std::future::poll_fn(|context| {
                match std::future::Future::poll(acquisition.as_mut(), context) {
                    std::task::Poll::Pending => std::task::Poll::Ready(()),
                    std::task::Poll::Ready(_) => panic!("barrier must still hold namespace"),
                }
            })
            .await;
            attempted.send(()).unwrap();
        }
        let result = acquisition.await;
        eprintln!(
            "copied queued lock returned: {} success={}",
            path.display(),
            result.is_ok()
        );
        result
    }

    async fn try_lock_existing_shared(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.inner.try_lock_existing_shared(path).await
    }

    async fn try_lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.inner.try_lock_existing_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.inner.read(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        self.inner.read_range(path, range).await
    }

    async fn read_ordinary_record(
        &self,
        request: crate::store::NativeOrdinaryRead,
    ) -> std::io::Result<Option<crate::store::NativeOrdinaryRecord>> {
        // Candidate history closes its original physical inputs through this
        // read-only recipe. Preserve the inner body traps and closing worker.
        self.inner.read_ordinary_record(request).await
    }

    async fn read_payload_ranges(
        &self,
        request: crate::store::NativePayloadRangeRead,
    ) -> std::io::Result<Option<crate::store::NativePayloadRangeRecord>> {
        // Retain the inner binding's forbidden-body observations while passing
        // the original sealed request through to the actual native worker.
        self.inner.read_payload_ranges(request).await
    }

    async fn write_new(&self, path: &Path, bytes: &[u8]) -> std::io::Result<()> {
        self.inner.write_new(path, bytes).await
    }

    async fn create_dir_all(&self, path: &Path) -> std::io::Result<()> {
        self.inner.create_dir_all(path).await
    }

    async fn read_dir(&self, path: &Path) -> std::io::Result<Vec<PathBuf>> {
        self.inner.read_dir(path).await
    }

    async fn metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        self.inner.metadata(path).await
    }

    async fn symlink_metadata(&self, path: &Path) -> std::io::Result<std::fs::Metadata> {
        self.inner.symlink_metadata(path).await
    }

    async fn symlink_metadata_batch(
        &self,
        paths: &[PathBuf],
    ) -> std::io::Result<Vec<std::io::Result<std::fs::Metadata>>> {
        self.inner.symlink_metadata_batch(paths).await
    }

    async fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        self.inner.remove_file(path).await
    }

    async fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.inner.rename(from, to).await
    }

    async fn rename_no_replace(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        self.inner.rename_no_replace(from, to).await
    }

    async fn sync_file(&self, path: &Path) -> std::io::Result<()> {
        self.inner.sync_file(path).await
    }

    async fn sync_directory(&self, path: &Path) -> std::io::Result<()> {
        self.inner.sync_directory(path).await
    }

    async fn read_nofollow(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.inner.read_nofollow(path).await
    }

    async fn list_xattrs(&self, path: &Path) -> std::io::Result<Vec<std::ffi::OsString>> {
        self.inner.list_xattrs(path).await
    }

    async fn get_xattr(
        &self,
        path: &Path,
        name: &std::ffi::OsStr,
    ) -> std::io::Result<Option<Vec<u8>>> {
        self.inner.get_xattr(path, name).await
    }

    async fn create_dir_new(&self, path: &Path) -> std::io::Result<()> {
        self.inner.create_dir_new(path).await
    }

    async fn set_permissions_and_sync(
        &self,
        path: &Path,
        permissions: std::fs::Permissions,
    ) -> std::io::Result<()> {
        self.inner.set_permissions_and_sync(path, permissions).await
    }
}

/// Owns a real payload whose native reads cannot be replaced by fixture data.
struct RangeFixture {
    root: PathBuf,
    path: PathBuf,
}

impl RangeFixture {
    async fn new(fs: &TestFs) -> Result<Self, Box<dyn std::error::Error>> {
        use std::os::unix::fs::DirBuilderExt;

        let entropy = fs.random_bytes(16).await?;
        let suffix: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let root = std::env::temp_dir().join(format!("terrane-copied-range-trap-{suffix}"));
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let path = root.join("data.pack");
        std::fs::write(&path, b"prefix--native-body--suffix")?;

        Ok(Self { root, path })
    }
}

impl Drop for RangeFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[tokio::test]
async fn copied_native_ranges_preserve_data_body_traps_for_reads_and_replay()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::store::native_publication_effects::PayloadRangeCapture;

    let inner = TestFs::default();
    let fixture = RangeFixture::new(&inner).await?;
    let fs = CopiedFs::new(inner.clone());
    let range = ByteRange {
        start: 8,
        length: 11,
    };

    assert!(PayloadRangeCapture::supported(&fs).await?);
    let mut capture = PayloadRangeCapture::capture_ordinary(&fs, &fixture.path).await?;
    assert_eq!(capture.len(), 27);
    assert_eq!(capture.read_range(&fs, range).await?, b"native-body");
    let retained = capture.finish();
    retained.revalidate(&fs).await?;
    assert_eq!(inner.data_body_read_attempts(), 0);
    assert_eq!(inner.effects(), 0);

    // Capture still opens and checks real descriptors while the body trap is
    // armed. Only a subsequent read or replay is a forbidden body attempt.
    inner.forbid_data_body_reads(std::slice::from_ref(&fixture.path))?;
    assert!(PayloadRangeCapture::supported(&fs).await?);
    let mut forbidden = PayloadRangeCapture::capture_ordinary(&fs, &fixture.path).await?;
    assert_eq!(inner.data_body_read_attempts(), 0);

    let error = forbidden.read_range(&fs, range).await.unwrap_err();
    assert_eq!(
        std::error::Error::source(&error).unwrap().to_string(),
        "forbidden data-pack body read"
    );
    assert_eq!(inner.data_body_read_attempts(), 1);

    let error = retained.revalidate(&fs).await.unwrap_err();
    assert_eq!(
        std::error::Error::source(&error).unwrap().to_string(),
        "forbidden data-pack body read"
    );
    assert_eq!(inner.data_body_read_attempts(), 2);
    assert_eq!(inner.effects(), 0);
    assert_eq!(
        std::fs::read(&fixture.path)?,
        b"prefix--native-body--suffix"
    );
    Ok(())
}
