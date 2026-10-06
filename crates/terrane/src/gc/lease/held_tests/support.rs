//! Retains real native factory setup and finite lease-worker instrumentation.

use super::super::fixture::{Fixture as OriginalFixture, Validator, configuration};
use crate::bucket::FileBucket;
use crate::gc::lease::{Collector, LeaseReceipt};
use crate::gc::runner::session::Session;
use crate::guard::Guard;
use crate::store::native_publication_effects::collection::test_fs::TestFs;
use crate::store::{
    ByteRange, Clock, EffectFault, EffectFaultProbe, LocalFs, NativeEffectClock,
    NativeEffectFailure, NativeFsEffect,
};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc,
};
use std::time::Duration;
use terrane_core::bucket::BucketKey;

/// Requires a successful fixture result or present native observation.
pub(super) trait Required<T> {
    /// Returns the independently asserted success value.
    ///
    /// # Panics
    /// Panics with the original diagnostic when setup/action fails or data is absent.
    #[track_caller]
    fn require(self) -> T;
}

impl<T, E: std::fmt::Debug> Required<T> for Result<T, E> {
    #[track_caller]
    fn require(self) -> T {
        match self {
            Ok(value) => value,
            Err(error) => panic!("required fixture operation failed: {error:?}"),
        }
    }
}

impl<T> Required<T> for Option<T> {
    #[track_caller]
    fn require(self) -> T {
        match self {
            Some(value) => value,
            None => panic!("required native fixture observation is absent"),
        }
    }
}

/// Requires an actual typed refusal rather than accepting successful fixture output.
pub(super) trait Rejected<E> {
    /// Returns the error from an independently asserted refused operation.
    ///
    /// # Panics
    /// Panics when the operation unexpectedly succeeds.
    #[track_caller]
    fn require_error(self) -> E;
}

impl<T, E> Rejected<E> for Result<T, E> {
    #[track_caller]
    fn require_error(self) -> E {
        match self {
            Err(error) => error,
            Ok(_) => panic!("native fixture operation unexpectedly succeeded"),
        }
    }
}

/// Names the actual reopened bucket with lease-only worker instrumentation.
pub(super) type Bucket = FileBucket<HeldFs, NativeEffectClock, Validator>;
/// Names the configured Guard used for genuine Collector and held factories.
pub(super) type ConcreteGuard = Guard<Bucket, NativeEffectClock>;

enum Hook {
    Noop,
    Fail {
        fault: EffectFault,
        swallow: bool,
    },
    Gate {
        arrived: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    },
}

/// Wraps the native filesystem without changing ordinary factory or I/O semantics.
#[derive(Clone)]
pub(super) struct HeldFs {
    inner: TestFs,
    hook: Arc<Mutex<Option<Hook>>>,
    locks: Arc<AtomicUsize>,
    syncs: Arc<Mutex<Option<mpsc::Sender<crate::store::LeaseSyncEvent>>>>,
}

impl HeldFs {
    /// Wraps the existing real native executor without supplying publication authority.
    pub(super) fn from_native(inner: TestFs) -> Self {
        Self {
            inner,
            hook: Arc::new(Mutex::new(None)),
            locks: Arc::new(AtomicUsize::new(0)),
            syncs: Arc::new(Mutex::new(None)),
        }
    }

    /// Observes only the next actual closed lease acknowledgment's completed syncs.
    ///
    /// # Panics
    /// Panics if fixture synchronization is poisoned or an observer remains pending.
    pub(super) fn observe_syncs(&self) -> mpsc::Receiver<crate::store::LeaseSyncEvent> {
        let (sender, receiver) = mpsc::channel();
        let mut pending = self.syncs.lock().require();
        assert!(pending.is_none());
        *pending = Some(sender);
        receiver
    }

    /// Returns actual namespace/control lock acquisitions since this observer began.
    pub(super) fn locks(&self) -> usize {
        self.locks.load(Ordering::SeqCst)
    }

    /// Returns actual submitted native effects, including refused acknowledgment.
    pub(super) fn effects(&self) -> usize {
        self.inner.effects()
    }

    /// Registers no-op unit success for exactly the next closed lease acknowledgment.
    ///
    /// # Panics
    /// Panics if fixture synchronization is poisoned or a prior hook remains.
    pub(super) fn noop(&self) {
        self.install(Hook::Noop);
    }

    /// Injects one actual lease-worker fault and optionally swallows its typed error.
    ///
    /// # Panics
    /// Panics if fixture synchronization is poisoned or a prior hook remains.
    pub(super) fn fault(&self, fault: EffectFault, swallow: bool) {
        self.install(Hook::Fail { fault, swallow });
    }

    /// Holds the actual closed lease worker at its native final-check boundary.
    ///
    /// # Panics
    /// Panics if fixture synchronization is poisoned or a prior hook remains.
    pub(super) fn pause(&self) -> (mpsc::Receiver<()>, mpsc::Sender<()>) {
        let (arrived, receiver) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        self.install(Hook::Gate {
            arrived,
            release: resume,
        });
        (receiver, release)
    }

    fn install(&self, hook: Hook) {
        let mut existing = self.hook.lock().require();
        assert!(existing.is_none());
        *existing = Some(hook);
    }

    /// Proves the registered hook reached the actual lease worker.
    ///
    /// # Panics
    /// Panics if synchronization is poisoned or the hook was not consumed.
    pub(super) fn assert_consumed(&self) {
        assert!(self.hook.lock().require().is_none());
    }
}

/// Retains original native initialization and genuinely bound administrative authority.
pub(super) struct Fixture {
    /// Genuine native initialization and independently bound original registration.
    pub(super) base: OriginalFixture,
    /// Actual configured Guard reopened through supported ordinary production setup.
    pub(super) guard: Arc<ConcreteGuard>,
    /// Transparent filesystem observer retaining real effects and finite hooks.
    pub(super) fs: HeldFs,
}

impl Fixture {
    /// Reopens real factory output with transparent lease-worker instrumentation.
    ///
    /// # Panics
    /// Panics if genuine factory initialization or supported ordinary reopen fails.
    pub(super) async fn new() -> Self {
        let base = OriginalFixture::new().await;
        let fs = HeldFs {
            inner: base.fs.clone(),
            hook: Arc::new(Mutex::new(None)),
            locks: Arc::new(AtomicUsize::new(0)),
            syncs: Arc::new(Mutex::new(None)),
        };
        let clock = base.clock.retain_native_clock().require();
        let bucket = FileBucket::open(base.config.clone(), fs.clone(), clock, Validator)
            .await
            .require();
        let guard = Arc::new(Guard::new(
            bucket,
            base.clock.retain_native_clock().require(),
            Vec::new(),
            configuration(),
        ));
        base.fs.reset();
        Self { base, guard, fs }
    }

    /// Borrows the actual maintenance configuration and original registration.
    pub(super) fn collector(
        &self,
    ) -> Collector<'_, HeldFs, NativeEffectClock, Validator, NativeEffectClock> {
        Collector::new(self.guard.as_ref(), &self.base.authority)
    }

    /// Retains exact consumed controls through the actual configured Guard factory.
    ///
    /// # Panics
    /// Panics if genuine configured registration/control retention fails.
    pub(super) async fn retained(
        &self,
        held: &crate::bucket::held::HeldBucket<'_, HeldFs, NativeEffectClock, Validator, true>,
    ) -> crate::guard::RetainedControls {
        let observed = held.observe_publication_unrepaired().await.require();
        let consumed =
            crate::guard::ConsumedResolver::new(self.guard.as_ref(), &self.base.authority)
                .require();
        consumed.registration(&self.base.authority).require();
        let snapshot = consumed.snapshot_bytes().require();
        assert_eq!(
            held.selected_guard_snapshot(&observed).await.require(),
            Some(snapshot)
        );
        let used = consumed.finish().require();
        let mut controls = self
            .guard
            .hold_original_registration(&self.base.authority, observed.identity())
            .await
            .require();
        controls.retain_used(&used.controls).await.require()
    }

    /// Acquires a real selected lease and retains its actual injected clock in Session.
    ///
    /// # Panics
    /// Panics if actual acquisition or the production Session initializer refuses.
    pub(super) async fn session(&self) -> (Session, LeaseReceipt) {
        let receipt = self.collector().acquire("held".into(), 20).await.require();
        let session = Session::from_receipt(
            receipt.clone(),
            20,
            self.base.clock.retain_native_clock().require(),
        )
        .require();
        (session, receipt)
    }

    /// Returns both genuine native coordination paths held by the context.
    ///
    /// # Panics
    /// Panics if the registered capabilities key cannot be parsed.
    pub(super) fn lock_paths(&self) -> [PathBuf; 2] {
        [
            self.base
                .config
                .root
                .join(BucketKey::parse("CAPABILITIES").require().lock_name()),
            self.base.authority.control().join("retention.lock"),
        ]
    }
}

/// Waits at the existing bounded native handoff without changing worker deadlines.
///
/// # Panics
/// Panics if the worker never reaches its genuine handoff or reports channel failure.
pub(super) async fn arrival(receiver: mpsc::Receiver<()>) {
    tokio::task::spawn_blocking(move || receiver.recv_timeout(Duration::from_secs(5)))
        .await
        .require()
        .require();
}

/// Proves actual kernel exclusion at both retained coordination inodes.
///
/// # Panics
/// Panics if either inode is unavailable or accepts a competing kernel lock.
pub(super) fn assert_excluded(paths: &[PathBuf; 2]) {
    for path in paths {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .require();
        assert!(matches!(
            file.try_lock(),
            Err(std::fs::TryLockError::WouldBlock)
        ));
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature = "send"), async_trait::async_trait(?Send))]
impl LocalFs for HeldFs {
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
        mut effect: NativeFsEffect,
    ) -> Result<(), NativeEffectFailure> {
        if matches!(
            effect.fault_probe(),
            EffectFaultProbe::SealLeasePublication(_)
        ) {
            let sender = self.syncs.lock().require().take();
            if let Some(sender) = sender {
                effect = effect.observe_lease_syncs(sender).require();
            }
        }
        let hook = if matches!(
            effect.fault_probe(),
            EffectFaultProbe::SealLeasePublication(_)
        ) {
            self.hook.lock().require().take()
        } else {
            None
        };
        let mut swallow = false;
        if let Some(hook) = hook {
            match hook {
                Hook::Noop => return Ok(()),
                Hook::Fail {
                    fault,
                    swallow: requested,
                } => {
                    effect = effect.inject_test_faults(vec![fault]);
                    swallow = requested;
                }
                Hook::Gate { arrived, release } => {
                    return tokio::task::spawn_blocking(move || {
                        arrived.send(()).require();
                        release.recv_timeout(Duration::from_secs(5)).require();
                        effect.execute_inline()
                    })
                    .await
                    .map_err(std::io::Error::other)?;
                }
            }
        }
        let result = self.inner.execute_retained_effect(effect).await;
        if swallow {
            match result {
                Err(NativeEffectFailure::Io(error)) => {
                    assert!(error.to_string().contains("injected creation"));
                    return Ok(());
                }
                other => panic!("actual injected native fault did not fail as expected: {other:?}"),
            }
        }
        result
    }

    async fn random_bytes(&self, length: usize) -> std::io::Result<Vec<u8>> {
        self.inner.random_bytes(length).await
    }

    async fn lock_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.locks.fetch_add(1, Ordering::SeqCst);
        self.inner.lock_exclusive(path).await
    }

    async fn lock_existing_exclusive(&self, path: &Path) -> std::io::Result<Self::Lock> {
        self.locks.fetch_add(1, Ordering::SeqCst);
        self.inner.lock_existing_exclusive(path).await
    }

    async fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.inner.read(path).await
    }

    async fn read_range(&self, path: &Path, range: ByteRange) -> std::io::Result<Vec<u8>> {
        self.inner.read_range(path, range).await
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
