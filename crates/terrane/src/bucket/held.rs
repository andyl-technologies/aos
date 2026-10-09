//! Holds one actual namespace exclusion or an ordered pair of exclusions.

#![allow(
    dead_code,
    reason = "Single and paired held adapters are separately integrated ref coordinator prerequisites."
)]

pub(crate) use super::content::BatchOutcome;
pub(crate) use super::content::held_nodes::NodeReads;

use super::{BucketBinding, FileBucket, files};
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, Clock, ContentStore, ContentUpload,
    ContentValidator, IdentityPrefix, LocalFs, RefCasOutcome, RefLogAppendOutcome, RefStore,
    RefWatch, StoreErrorKind, StoreFailure,
};
use std::sync::Arc;
use terrane_core::bucket::BucketKey;
use terrane_core::identity::Identity;
use terrane_core::refs::{RefLogRecord, RefRecord};

#[derive(Clone, Copy, PartialEq, Eq)]
struct PhysicalIdentity {
    root: (u64, u64),
    lock: (u64, u64),
}

async fn identity<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
>(
    bucket: &FileBucket<F, C, V>,
) -> Result<PhysicalIdentity, StoreFailure> {
    let key = BucketKey::parse("CAPABILITIES").map_err(|_| files::malformed())?;
    let root = bucket
        .inner
        .fs
        .symlink_metadata(bucket.root())
        .await
        .map_err(files::io_failure)?;
    let lock = bucket
        .inner
        .fs
        .symlink_metadata(&bucket.root().join(key.lock_name()))
        .await
        .map_err(files::io_failure)?;
    if !root.is_dir()
        || root.file_type().is_symlink()
        || !lock.is_file()
        || lock.file_type().is_symlink()
    {
        return Err(files::layout_corrupt());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(PhysicalIdentity {
            root: (root.dev(), root.ino()),
            lock: (lock.dev(), lock.ino()),
        })
    }
    #[cfg(not(unix))]
    {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}

/// Keeps genuine descriptor retention separate from read-only unavailability.
#[derive(Clone)]
enum NamespaceRetention {
    Available(Arc<crate::store::NativeExclusion>),
    Unavailable,
}

impl NamespaceRetention {
    fn capture<F: LocalFs>(fs: &F, guard: &F::Lock) -> Result<Self, StoreFailure> {
        match fs.retain_native_exclusion(guard) {
            Ok(receipt) => Ok(Self::Available(Arc::new(receipt))),
            Err(error) if error.kind() == std::io::ErrorKind::Unsupported => Ok(Self::Unavailable),
            Err(error) => Err(files::io_failure(error)),
        }
    }

    fn receipt(&self) -> Result<&crate::store::NativeExclusion, StoreFailure> {
        match self {
            Self::Available(receipt) => Ok(receipt),
            Self::Unavailable => Err(StoreFailure::new(StoreErrorKind::Unsupported)),
        }
    }
}

/// Retains one actual namespace guard for source and destination roles.
///
/// Both adapters borrow this holder, so neither can outlive its exclusion.
pub(crate) struct SingleHeld<'a, F: LocalFs, C, V> {
    bucket: &'a FileBucket<F, C, V>,
    identity: PhysicalIdentity,
    retention: NamespaceRetention,
    write_allowed: bool,
    _guard: F::Lock,
}

impl<'a, F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    SingleHeld<'a, F, C, V>
{
    /// Acquires and revalidates one actual writable namespace exclusion.
    ///
    /// # Errors
    /// Rejects legacy read-only access before effects, unsafe or changed physical
    /// identities, incompatible selected layouts, and unavailable locking.
    pub(crate) async fn acquire(bucket: &'a FileBucket<F, C, V>) -> Result<Self, StoreFailure> {
        if bucket.inner.access.read_only() {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }

        let checked_identity = identity(bucket).await?;
        let guard = bucket.existing_exclusive().await?;
        if identity(bucket).await? != checked_identity {
            return Err(files::layout_corrupt());
        }
        let retention = NamespaceRetention::capture(&bucket.inner.fs, &guard)?;
        retention.receipt()?;
        if identity(bucket).await? != checked_identity {
            return Err(files::layout_corrupt());
        }
        bucket.write_layout_locked().await?;

        Ok(Self {
            bucket,
            identity: checked_identity,
            retention,
            write_allowed: true,
            _guard: guard,
        })
    }

    /// Retains an already acquired namespace guard after Active registration checks.
    ///
    /// The activation path supplies the actual existing-only guard while it still
    /// holds the exact registration read. Full selected layout verification
    /// precedes construction of a writable adapter; no format record mints it.
    ///
    /// # Errors
    /// Rejects read-only access, unavailable native descriptor retention, changed
    /// physical identities and incomplete or incompatible Active selected state.
    pub(in crate::bucket) async fn from_active_guard(
        bucket: &'a FileBucket<F, C, V>,
        guard: F::Lock,
    ) -> Result<Self, StoreFailure> {
        if bucket.inner.access.read_only() {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        let checked_identity = identity(bucket).await?;
        let retention = NamespaceRetention::capture(&bucket.inner.fs, &guard)?;
        retention.receipt()?;
        if identity(bucket).await? != checked_identity {
            return Err(files::layout_corrupt());
        }

        bucket.write_layout_locked().await?;
        if identity(bucket).await? != checked_identity {
            return Err(files::layout_corrupt());
        }
        Ok(Self {
            bucket,
            identity: checked_identity,
            retention,
            write_allowed: true,
            _guard: guard,
        })
    }

    /// Acquires an actual namespace for reads without requiring native effects.
    ///
    /// Missing native retention stays explicit and cannot be used for repair,
    /// staging or publication. No layout repair or effect occurs on this path.
    ///
    /// # Errors
    /// Rejects legacy access requiring unsupported exclusion, changed physical
    /// identities, incompatible selected layouts and failed descriptor retention.
    pub(crate) async fn acquire_read_only(
        bucket: &'a FileBucket<F, C, V>,
    ) -> Result<Self, StoreFailure> {
        if bucket.inner.access.read_only() {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        let checked_identity = identity(bucket).await?;
        let guard = bucket.existing_exclusive().await?;
        if identity(bucket).await? != checked_identity {
            return Err(files::layout_corrupt());
        }
        let retention = NamespaceRetention::capture(&bucket.inner.fs, &guard)?;
        if identity(bucket).await? != checked_identity {
            return Err(files::layout_corrupt());
        }
        bucket.ensure_layout().await?;
        Ok(Self {
            bucket,
            identity: checked_identity,
            retention,
            write_allowed: false,
            _guard: guard,
        })
    }

    /// Borrows a read-only source adapter under the single retained exclusion.
    pub(crate) fn source(&self) -> HeldBucket<'_, F, C, V, false> {
        HeldBucket {
            bucket: self.bucket,
            identity: self.identity,
            retention: self.retention.clone(),
            write_allowed: self.write_allowed,
        }
    }

    /// Borrows a durable destination adapter under the same retained exclusion.
    pub(crate) fn destination(&self) -> HeldBucket<'_, F, C, V, true> {
        HeldBucket {
            bucket: self.bucket,
            identity: self.identity,
            retention: self.retention.clone(),
            write_allowed: self.write_allowed,
        }
    }
}

/// Retains both namespace guards until the transaction or cancellation finishes.
pub(crate) struct HeldBuckets<'a, F: LocalFs, C, V, G: LocalFs, D, W> {
    source: &'a FileBucket<F, C, V>,
    destination: &'a FileBucket<G, D, W>,
    source_identity: PhysicalIdentity,
    destination_identity: PhysicalIdentity,
    source_retention: NamespaceRetention,
    destination_retention: NamespaceRetention,
    _source_guard: F::Lock,
    _destination_guard: G::Lock,
}

impl<
    'a,
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    G: LocalFs + BucketBinding,
    D: Clock + BucketBinding,
    W: ContentValidator + BucketBinding,
> HeldBuckets<'a, F, C, V, G, D, W>
{
    /// Acquires distinct physical namespaces without inverse-transaction deadlock.
    ///
    /// # Errors
    /// Rejects aliases, changed identities, unsafe layout, and unavailable locking.
    pub(crate) async fn acquire(
        source: &'a FileBucket<F, C, V>,
        destination: &'a FileBucket<G, D, W>,
    ) -> Result<Self, StoreFailure> {
        if source.inner.access.read_only() || destination.inner.access.read_only() {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        let source_id = identity(source).await?;
        let destination_id = identity(destination).await?;
        if source_id.root == destination_id.root || source_id.lock == destination_id.lock {
            return Err(files::malformed());
        }
        // Every transaction orders actual namespace identities, even when its
        // source and destination roles are reversed. A hard-linked lock inode
        // is rejected above rather than attempting to acquire it twice.
        let (source_guard, source_retention, destination_guard, destination_retention) =
            if source_id.root < destination_id.root {
                let first = source.existing_exclusive().await?;
                let source_retention = NamespaceRetention::capture(&source.inner.fs, &first)?;
                source_retention.receipt()?;
                recheck(source, destination, source_id, destination_id).await?;
                let second = destination.existing_exclusive().await?;
                let destination_retention =
                    NamespaceRetention::capture(&destination.inner.fs, &second)?;
                destination_retention.receipt()?;
                (first, source_retention, second, destination_retention)
            } else {
                let first = destination.existing_exclusive().await?;
                let destination_retention =
                    NamespaceRetention::capture(&destination.inner.fs, &first)?;
                destination_retention.receipt()?;
                recheck(source, destination, source_id, destination_id).await?;
                let second = source.existing_exclusive().await?;
                let source_retention = NamespaceRetention::capture(&source.inner.fs, &second)?;
                source_retention.receipt()?;
                (second, source_retention, first, destination_retention)
            };
        recheck(source, destination, source_id, destination_id).await?;
        source.write_layout_locked().await?;
        destination.write_layout_locked().await?;
        Ok(Self {
            source,
            destination,
            source_identity: source_id,
            destination_identity: destination_id,
            source_retention,
            destination_retention,
            _source_guard: source_guard,
            _destination_guard: destination_guard,
        })
    }

    /// Borrows a read-only source adapter for the lifetime of the held pair.
    ///
    /// Its lifetime follows this borrow, so the adapter cannot outlive the guards.
    pub(crate) fn source(&self) -> HeldBucket<'_, F, C, V, false> {
        HeldBucket {
            bucket: self.source,
            identity: self.source_identity,
            retention: self.source_retention.clone(),
            write_allowed: true,
        }
    }

    /// Borrows the durable destination adapter for the lifetime of the held pair.
    pub(crate) fn destination(&self) -> HeldBucket<'_, G, D, W, true> {
        HeldBucket {
            bucket: self.destination,
            identity: self.destination_identity,
            retention: self.destination_retention.clone(),
            write_allowed: true,
        }
    }
}

async fn recheck<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    G: LocalFs + BucketBinding,
    D: Clock + BucketBinding,
    W: ContentValidator + BucketBinding,
>(
    source: &FileBucket<F, C, V>,
    destination: &FileBucket<G, D, W>,
    source_id: PhysicalIdentity,
    destination_id: PhysicalIdentity,
) -> Result<(), StoreFailure> {
    if identity(source).await? != source_id || identity(destination).await? != destination_id {
        return Err(files::layout_corrupt());
    }
    Ok(())
}

/// Borrows synchronization evidence from a live single or paired namespace exclusion.
///
/// This proof identifies a held namespace and adapter role; it does not authorize
/// an actor, disclosure, or mutation independently of repository checks.
pub(crate) struct HeldIdentity<'guard> {
    root: &'guard std::path::Path,
    identity: PhysicalIdentity,
    retention: &'guard NamespaceRetention,
    writable: bool,
}

impl HeldIdentity<'_> {
    /// Returns the configured root whose physical identity was rechecked.
    pub(crate) fn root(&self) -> &std::path::Path {
        self.root
    }

    /// Returns the checked root and stable coordination device/inode pairs.
    pub(crate) fn physical_identity(&self) -> ((u64, u64), (u64, u64)) {
        (self.identity.root, self.identity.lock)
    }

    /// Borrows the actual held descriptor receipt without exposing its descriptor.
    ///
    /// # Errors
    /// Refuses unavailable native retention; read-only observation creates none.
    pub(crate) fn retained_namespace(
        &self,
    ) -> Result<&crate::store::NativeExclusion, StoreFailure> {
        self.retention.receipt()
    }

    /// Reports the existing adapter role rather than caller-supplied authority.
    pub(crate) fn writable(&self) -> bool {
        self.writable
    }
}

/// Borrows an already excluded bucket without exposing its guard or reacquiring it.
pub(crate) struct HeldBucket<'a, F, C, V, const WRITABLE: bool> {
    bucket: &'a FileBucket<F, C, V>,
    identity: PhysicalIdentity,
    retention: NamespaceRetention,
    write_allowed: bool,
}

impl<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    const WRITABLE: bool,
> HeldBucket<'_, F, C, V, WRITABLE>
{
    /// Borrows proof of this adapter's live single or paired namespace exclusion.
    pub(crate) fn identity_proof(&self) -> HeldIdentity<'_> {
        HeldIdentity {
            root: self.bucket.root(),
            identity: self.identity,
            retention: &self.retention,
            writable: WRITABLE && self.write_allowed,
        }
    }

    /// Requires actual descriptor retention before a writable physical operation.
    ///
    /// # Errors
    /// Refuses unsupported retention or a read-only actual holder/adapter role.
    pub(crate) fn retained_namespace(
        &self,
    ) -> Result<&crate::store::NativeExclusion, StoreFailure> {
        let receipt = self.retention.receipt()?;
        if !WRITABLE || !self.write_allowed {
            return Err(StoreFailure::new(StoreErrorKind::ReadOnly));
        }
        Ok(receipt)
    }

    /// Returns the root and coordination inode identities rechecked under the retained exclusion.
    ///
    /// These device/inode pairs identify the namespace while the borrowed namespace
    /// guard lives. They do not independently authorize disclosure or mutation.
    pub(crate) fn physical_identity(&self) -> ((u64, u64), (u64, u64)) {
        (self.identity.root, self.identity.lock)
    }

    /// Returns the actual configured filesystem for private disclosure binding checks.
    pub(crate) fn fs(&self) -> &F {
        self.bucket.fs()
    }

    /// Returns the configured namespace for private disclosure binding checks.
    pub(crate) fn root(&self) -> &std::path::Path {
        self.bucket.root()
    }

    /// Borrows the backend without acquiring another namespace exclusion.
    pub(super) fn bucket(&self) -> &FileBucket<F, C, V> {
        self.bucket
    }
}

impl<F, C, V, const WRITABLE: bool> CapabilityReport for HeldBucket<'_, F, C, V, WRITABLE> {
    fn capabilities(&self) -> &Capabilities {
        self.bucket.capabilities()
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature="send"),async_trait::async_trait(?Send))]
impl<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    const WRITABLE: bool,
> ContentStore for HeldBucket<'_, F, C, V, WRITABLE>
{
    async fn put(&self, upload: ContentUpload<'_>) -> Result<Identity, StoreFailure> {
        self.retained_namespace()?;
        self.bucket.put_locked(self, upload).await
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.bucket.get_held(self, identity, range).await
    }

    async fn has(&self, identities: &[Identity]) -> Result<Vec<bool>, StoreFailure> {
        self.bucket.has_locked(identities).await
    }

    async fn list(&self, prefix: &IdentityPrefix) -> Result<Vec<Identity>, StoreFailure> {
        self.bucket.list_locked(prefix).await
    }
}

/// Rejects live watching during a bounded held transaction.
pub(crate) struct HeldWatch;

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature="send"),async_trait::async_trait(?Send))]
impl RefWatch for HeldWatch {
    async fn next(&mut self) -> Result<Option<RefLogRecord>, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}

#[cfg_attr(feature = "send", async_trait::async_trait)]
#[cfg_attr(not(feature="send"),async_trait::async_trait(?Send))]
impl<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    const WRITABLE: bool,
> RefStore for HeldBucket<'_, F, C, V, WRITABLE>
{
    type Watch = HeldWatch;

    async fn ref_get(&self, name: &str) -> Result<Option<RefRecord>, StoreFailure> {
        self.read_selected_ref(name).await
    }

    async fn ref_cas(
        &self,
        name: &str,
        expect: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        self.retained_namespace()?;
        self.cas_raw_ref(name, expect, new).await
    }

    async fn ref_log_append(
        &self,
        name: &str,
        seq: u64,
        record: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        self.retained_namespace()?;
        let observed = self.observe_publication().await?;
        crate::store::native_publication_effects::stage_ref_log(
            self.fs(),
            &observed,
            name,
            seq,
            record,
        )
        .await
    }

    async fn ref_log_read(
        &self,
        name: &str,
        from_seq: u64,
    ) -> Result<Vec<RefLogRecord>, StoreFailure> {
        self.bucket.ref_log_read_locked(name, from_seq).await
    }

    async fn ref_watch(&self, _name: &str, _from_seq: u64) -> Result<Self::Watch, StoreFailure> {
        Err(StoreFailure::new(StoreErrorKind::Unsupported))
    }
}

impl<F, C, V> HeldBucket<'_, F, C, V, true>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    /// Executes a metadata run beneath the actual held native publication.
    ///
    /// # Errors
    /// Preserves ordinary validation and retained native publication failures.
    pub(crate) async fn put_meta_batch(
        &self,
        uploads: &[crate::store::MetaUpload<'_>],
        context: &crate::selected_bridge::native_guard::meta_batch::ImmutableEffectContext<'_, '_>,
    ) -> Result<BatchOutcome, StoreFailure> {
        self.retained_namespace()?;
        self.bucket
            .put_meta_batch_locked(self, uploads, context)
            .await
    }

    /// Performs an ordinary fallback while retaining actual native checks.
    ///
    /// # Errors
    /// Preserves ordinary failures; direct Pack import needs its separate context
    /// path and is explicitly unsupported here until that path is implemented.
    pub(crate) async fn put_contextual(
        &self,
        upload: ContentUpload<'_>,
        context: &crate::selected_bridge::native_guard::meta_batch::ImmutableEffectContext<'_, '_>,
    ) -> Result<Identity, StoreFailure> {
        self.retained_namespace()?;
        self.bucket
            .put_locked_contextual(self, upload, Some(context))
            .await
    }
}
