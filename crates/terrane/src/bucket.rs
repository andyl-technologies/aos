//! Owns the file bucket backend over configured filesystem, clock, and validator bindings.
//!
//! Registered immutable keys use synced temporary files and atomic installation.
//! One persistent exclusion inode fences each complete compare-and-swap; its
//! guard is retained through directory synchronization. Content is opaque to
//! the backend and format validation is delegated to the configured validator.

mod access;
use access::Access;

mod catalog;
mod containers;
mod content;
mod files;
pub(crate) mod held;
#[cfg(all(test, feature = "tokio", unix))]
mod held_tests;
pub(crate) mod publication;
mod quarantine;
mod retirement;

mod refs;
#[cfg(all(test, feature = "tokio"))]
mod retirement_tests;

#[cfg(all(test, feature = "tokio"))]
mod readmission_tests;

#[cfg(all(test, feature = "tokio"))]
mod selection_tests;

#[cfg(all(test, feature = "tokio"))]
mod version_tests;

#[cfg(all(test, feature = "tokio"))]
mod tests;

#[cfg(all(test, feature = "tokio"))]
mod fault_tests;

#[cfg(all(test, feature = "tokio"))]
mod content_tests;

#[cfg(all(test, feature = "tokio"))]
mod manifest_tests;

#[cfg(all(test, feature = "tokio"))]
mod container_tests;

use crate::store::{
    Capabilities, CapabilityReport, Clock, ContentValidator, Durability, LocalFs, RangeCapability,
    RefCapability, StoreErrorKind, StoreFailure,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(all(test, feature = "tokio"))]
use terrane_core::bucket::BucketCapabilities;
use terrane_core::bucket::{BucketKey, StoreProfile};
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
    /// Independently configured protected publication control, when supported.
    /// Configuration alone grants no fresh registration or publication authority.
    pub publication_control: Option<FileBucketPublicationConfig>,
}

/// Configures the protected owner and location of file-bucket publication control.
///
/// Native registration separately verifies the opened physical binding and
/// complete selected evidence. These fields do not establish those facts.
#[derive(Clone, Debug)]
pub struct FileBucketPublicationConfig {
    /// The independently configured operator's Unix user identifier.
    pub operator_uid: u32,
    /// An explicit protected control directory outside the portable payload.
    /// Absence selects the registered external sibling location.
    pub control: Option<PathBuf>,
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
    access: Access,
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
    /// Opens a registered writable bucket, atomically creating its absent root.
    ///
    /// The configured root's parent must exist, and protected publication
    /// ownership must be configured independently. Only the successful root
    /// creator may initialize the empty selected inventory. Existing roots must
    /// recover their exact protected registration and selected publication chain
    /// before probes or cache reads. Version one requires explicit read-only
    /// access; migration requires complete inventory and external writer fencing.
    ///
    /// # Errors
    /// Refuses absent protected configuration, malformed or incompatible
    /// registration/profile records, failed probes, unsupported profile
    /// parameters, unsafe paths, and unavailable durable I/O.
    pub async fn open(
        config: FileBucketConfig,
        fs: F,
        clock: C,
        validator: V,
    ) -> Result<Self, StoreFailure> {
        if !config.root.is_absolute()
            || config.publication_control.is_none()
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
                access: Access::Writable,
            }),
        };

        bucket.preflight_publication_namespace().await?;

        let freshly_created = match bucket
            .inner
            .fs
            .symlink_metadata(&bucket.inner.config.root)
            .await
        {
            Ok(_) => false,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                match bucket
                    .inner
                    .fs
                    .create_dir_new(&bucket.inner.config.root)
                    .await
                {
                    Ok(()) => {
                        let parent = bucket
                            .inner
                            .config
                            .root
                            .parent()
                            .ok_or_else(files::malformed)?;
                        bucket
                            .inner
                            .fs
                            .sync_directory(parent)
                            .await
                            .map_err(files::io_failure)?;
                        true
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => false,
                    Err(error) => return Err(files::io_failure(error)),
                }
            }
            Err(error) => return Err(files::io_failure(error)),
        };
        bucket.check_directory(&bucket.inner.config.root).await?;
        bucket.open_publication(freshly_created).await?;
        {
            let _guard = bucket.exclusive().await?;
            bucket.catalog().await?;
        }
        Ok(bucket)
    }

    /// Opens existing layout one without any writes or startup mutation probes.
    ///
    /// Ref and numbered-log reads use their original locations. Every effect is
    /// refused, and a layout transition requires reopening. This constructor
    /// neither creates the root nor upgrades unknown inventory completeness.
    ///
    /// # Errors
    /// Refuses absent, unsafe, corrupt, unsupported or incompatible namespaces,
    /// failed read-range verification, changed layouts, and unavailable reads.
    pub async fn open_legacy_read_only(
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
            refs: RefCapability::None,
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
                access: Access::LegacyReadOnly,
            }),
        };

        bucket.check_directory(bucket.root()).await?;
        bucket.ensure_layout().await?;
        let key = BucketKey::parse("CAPABILITIES").map_err(|_| files::malformed())?;
        let current = bucket
            .read_optional(&key)
            .await?
            .ok_or_else(files::layout_corrupt)?;
        let ranged = bucket
            .inner
            .fs
            .read_range(
                &bucket.path(&key),
                crate::store::ByteRange {
                    start: 0,
                    length: 1,
                },
            )
            .await
            .map_err(files::io_failure)?;
        let first_byte = current.get(..1).ok_or_else(files::layout_corrupt)?;
        if ranged.as_slice() != first_byte {
            return Err(StoreFailure::new(StoreErrorKind::Unsupported));
        }
        bucket.catalog().await?;
        bucket.ensure_layout().await?;
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

    /// Borrows the actual configured filesystem binding for internal authority checks.
    #[allow(
        dead_code,
        reason = "The D74 domain signing adapter is integrated separately."
    )]
    pub(crate) fn fs(&self) -> &F {
        &self.inner.fs
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

#[cfg(all(test, feature = "tokio"))]
mod requirement_tests;
