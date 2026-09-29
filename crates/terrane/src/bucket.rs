//! Owns the file bucket backend over configured filesystem, clock, and validator bindings.
//!
//! Registered immutable keys use synced temporary files and atomic installation.
//! One persistent exclusion inode fences each complete compare-and-swap; its
//! guard is retained through directory synchronization. Content is opaque to
//! the backend and format validation is delegated to the configured validator.

mod catalog;
mod containers;
mod content;
mod files;
mod quarantine;
mod refs;

#[cfg(all(test, feature = "tokio"))]
mod tests;

#[cfg(all(test, feature = "tokio"))]
mod fault_tests;

#[cfg(all(test, feature = "tokio"))]
mod content_tests;

use crate::store::{
    Capabilities, CapabilityReport, Clock, ContentValidator, Durability, LocalFs, RangeCapability,
    RefCapability, StoreErrorKind, StoreFailure,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use terrane_core::bucket::{BucketCapabilities, BucketKey, StoreProfile};
use terrane_core::chunking::ChunkProfile;
use terrane_core::refs::Locality;

/// Requires binding safety only when the portable send feature is selected.
#[cfg(feature = "send")]
pub trait BucketBinding: Send + Sync {}
#[cfg(feature = "send")]
impl<T: Send + Sync> BucketBinding for T {}

/// Permits local-only bindings when send futures are not requested.
#[cfg(not(feature = "send"))]
pub trait BucketBinding {}
#[cfg(not(feature = "send"))]
impl<T> BucketBinding for T {}

/// Configures the immutable profile and locality of one file bucket.
#[derive(Clone, Debug)]
pub struct FileBucketConfig {
    /// The root directory holding the portable registered layout.
    pub root: PathBuf,
    /// The registered chunk profile name.
    pub chunk_profile_name: String,
    /// The profile used to validate every chunk admission.
    pub chunk_profile: ChunkProfile,
    /// The placement labels reported to callers.
    pub locality: Locality,
}

/// Holds a file bucket with explicitly configured portable I/O bindings.
pub struct FileBucket<F, C, V> {
    inner: Arc<Inner<F, C, V>>,
}

struct Inner<F, C, V> {
    config: FileBucketConfig,
    fs: F,
    clock: C,
    validator: V,
    capabilities: Capabilities,
}

impl<F, C, V> Clone for FileBucket<F, C, V> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Opens and probes a bucket without trusting persisted capabilities.
    ///
    /// # Errors
    /// Refuses malformed or incompatible layout/profile records, failed probes,
    /// unsupported profile parameters, unsafe paths, and unavailable durable I/O.
    pub async fn open(
        config: FileBucketConfig,
        fs: F,
        clock: C,
        validator: V,
    ) -> Result<Self, StoreFailure> {
        if !config.root.is_absolute()
            || config.chunk_profile_name != "cdc-1m"
            || config.chunk_profile != ChunkProfile::cdc_1m(config.chunk_profile.seed())
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }

        let capabilities = Capabilities {
            refs: RefCapability::Cas,
            ranges: RangeCapability::Ranges,
            presign: false,
            locality: config.locality.clone(),
            durability: Durability::Local,
            sealed: false,
        };

        let bucket = Self {
            inner: Arc::new(Inner {
                config,
                fs,
                clock,
                validator,
                capabilities,
            }),
        };

        bucket
            .inner
            .fs
            .create_dir_all(&bucket.inner.config.root)
            .await
            .map_err(files::io_failure)?;
        bucket.check_directory(&bucket.inner.config.root).await?;
        bucket.probe().await?;
        {
            let _guard = bucket.exclusive().await?;
            bucket.catalog().await?;
        }
        Ok(bucket)
    }

    fn profile(&self) -> StoreProfile {
        StoreProfile {
            identity: "terrane-v1".into(),
            algorithm: "blake3".into(),
            chunk: self.inner.config.chunk_profile_name.clone(),
            seed: self.inner.config.chunk_profile.seed(),
        }
    }

    async fn probe(&self) -> Result<(), StoreFailure> {
        let key = BucketKey::parse("CAPABILITIES").map_err(|_| files::malformed())?;
        let _guard = self.exclusive().await?;
        let old = self.read_optional(&key).await?;
        let mut generation = None;
        if let Some(bytes) = &old {
            let record = BucketCapabilities::decode(bytes).map_err(|_| files::layout_corrupt())?;
            generation = record.generation;
            if record.profile != self.profile() {
                return Err(StoreFailure::new(StoreErrorKind::Unsupported));
            }
        } else {
            // Existing portable state without its layout/profile binding is
            // never reinterpreted as a new empty store.
            for prefix in ["objects", "refs", "logs", "gc", "trash"] {
                match self
                    .inner
                    .fs
                    .symlink_metadata(&self.inner.config.root.join(prefix))
                    .await
                {
                    Ok(_) => return Err(files::layout_corrupt()),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(files::io_failure(error)),
                }
            }
        }

        let timestamp = self
            .inner
            .clock
            .now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map_err(|_| files::malformed())?
            .as_secs();
        let record = BucketCapabilities {
            layout_version: 1,
            create_if_absent: true,
            compare_and_swap: true,
            ranges: true,
            presign: false,
            multi_writer: true,
            probed_at: timestamp,
            generation,
            profile: self.profile(),
        };
        let bytes = record.encode().map_err(|_| files::malformed())?;
        if old.is_none() {
            self.install(&key, &bytes, false).await?;
        }

        // Both probes operate on the actual persisted key through the same
        // conditional primitives used by ordinary writes.
        if self
            .install(&key, b"must never become visible", false)
            .await?
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let current = self
            .read_optional(&key)
            .await?
            .ok_or_else(files::layout_corrupt)?;
        let mut stale = current.clone();
        stale.push(0);
        if self
            .replace_conditionally(&key, Some(&stale), b"must never become visible")
            .await?
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        let path = self.path(&key);
        let range = self
            .inner
            .fs
            .read_range(
                &path,
                crate::store::ByteRange {
                    start: 0,
                    length: 1,
                },
            )
            .await
            .map_err(files::io_failure)?;
        if range != current[..1] {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        if !self
            .replace_conditionally(&key, Some(&current), &bytes)
            .await?
        {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        Ok(())
    }

    fn path(&self, key: &BucketKey) -> PathBuf {
        self.inner.config.root.join(key.as_str())
    }

    /// Returns the configured root of the portable bucket layout.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.inner.config.root
    }
}

impl<F, C, V> CapabilityReport for FileBucket<F, C, V> {
    fn capabilities(&self) -> &Capabilities {
        &self.inner.capabilities
    }
}
