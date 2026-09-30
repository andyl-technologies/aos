//! Holds two actual bucket exclusions in physical identity order.

#![allow(
    dead_code,
    reason = "The paired adapter is a separately integrated ref coordinator prerequisite."
)]

use super::{BucketBinding, FileBucket, files};
use crate::store::{
    ByteRange, Capabilities, CapabilityReport, Clock, ContentStore, ContentUpload,
    ContentValidator, IdentityPrefix, LocalFs, RefCasOutcome, RefLogAppendOutcome, RefStore,
    RefWatch, StoreErrorKind, StoreFailure,
};
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

/// Retains both namespace guards until the transaction or cancellation finishes.
pub(crate) struct HeldBuckets<'a, F: LocalFs, C, V, G: LocalFs, D, W> {
    source: &'a FileBucket<F, C, V>,
    destination: &'a FileBucket<G, D, W>,
    source_identity: PhysicalIdentity,
    destination_identity: PhysicalIdentity,
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
        let source_id = identity(source).await?;
        let destination_id = identity(destination).await?;
        if source_id.root == destination_id.root || source_id.lock == destination_id.lock {
            return Err(files::malformed());
        }
        // Every transaction orders actual namespace identities, even when its
        // source and destination roles are reversed. A hard-linked lock inode
        // is rejected above rather than attempting to acquire it twice.
        let (source_guard, destination_guard) = if source_id.root < destination_id.root {
            let first = source.exclusive().await?;
            recheck(source, destination, source_id, destination_id).await?;
            (first, destination.exclusive().await?)
        } else {
            let first = destination.exclusive().await?;
            recheck(source, destination, source_id, destination_id).await?;
            (source.exclusive().await?, first)
        };
        recheck(source, destination, source_id, destination_id).await?;
        Ok(Self {
            source,
            destination,
            source_identity: source_id,
            destination_identity: destination_id,
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
        }
    }

    /// Borrows the durable destination adapter for the lifetime of the held pair.
    pub(crate) fn destination(&self) -> HeldBucket<'_, G, D, W, true> {
        HeldBucket {
            bucket: self.destination,
            identity: self.destination_identity,
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

/// Borrows an already excluded bucket without exposing its guard or reacquiring it.
pub(crate) struct HeldBucket<'a, F, C, V, const WRITABLE: bool> {
    bucket: &'a FileBucket<F, C, V>,
    identity: PhysicalIdentity,
}

impl<
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
    const WRITABLE: bool,
> HeldBucket<'_, F, C, V, WRITABLE>
{
    /// Returns the root and coordination inode identities rechecked under both guards.
    ///
    /// These device/inode pairs identify the namespace while the borrowed pair
    /// guards live. They do not independently authorize disclosure or mutation.
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
}

impl<F, C, V, const WRITABLE: bool> CapabilityReport for HeldBucket<'_, F, C, V, WRITABLE> {
    fn capabilities(&self) -> &Capabilities {
        self.bucket.capabilities()
    }
}

fn writable<const WRITABLE: bool>() -> Result<(), StoreFailure> {
    if WRITABLE {
        Ok(())
    } else {
        Err(StoreFailure::new(StoreErrorKind::ReadOnly))
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
        writable::<WRITABLE>()?;
        self.bucket.put_locked(upload).await
    }

    async fn get(
        &self,
        identity: &Identity,
        range: Option<ByteRange>,
    ) -> Result<Vec<u8>, StoreFailure> {
        self.bucket.get_locked(identity, range).await
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
        self.bucket.ref_get_locked(name).await
    }

    async fn ref_cas(
        &self,
        name: &str,
        expect: Option<&RefRecord>,
        new: &RefRecord,
    ) -> Result<RefCasOutcome, StoreFailure> {
        writable::<WRITABLE>()?;
        self.bucket.ref_cas_locked(name, expect, new).await
    }

    async fn ref_log_append(
        &self,
        name: &str,
        seq: u64,
        record: &RefLogRecord,
    ) -> Result<RefLogAppendOutcome, StoreFailure> {
        writable::<WRITABLE>()?;
        self.bucket.ref_log_append_locked(name, seq, record).await
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
