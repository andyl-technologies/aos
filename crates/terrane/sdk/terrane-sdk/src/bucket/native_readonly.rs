//! Reopens protected native publication for reads without startup mutations.

use super::{Access, BucketBinding, FileBucket, FileBucketConfig, Inner};
use crate::store::{
    Capabilities, Clock, ContentValidator, Durability, LocalFs, RangeCapability, RefCapability,
    StoreErrorKind, StoreFailure,
};
use std::sync::Arc;
use terrane_format::chunking::ChunkProfile;

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Reopens an active original registration without initializing or repairing it.
    ///
    /// Selected reads retain the native exclusion and complete publication
    /// validation. The handle advertises no ref-write capability and refuses
    /// every mutable holder, including when its backing mount is writable.
    ///
    /// # Errors
    /// Refuses missing or pending registration, unsafe physical controls,
    /// incompatible profiles, incomplete selected evidence and failed native I/O.
    pub(crate) async fn open_existing_read_only(
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
                access: Access::NativeReadOnly,
                #[cfg(all(test, feature = "tokio", unix))]
                content_observation: Arc::default(),
            }),
        };
        bucket.preflight_publication_namespace().await?;
        bucket.check_directory(bucket.root()).await?;
        bucket.verify_read_only_publication().await?;
        let _guard = bucket.existing_exclusive().await?;
        bucket.catalog().await?;
        Ok(bucket)
    }

    /// Identifies the private native read-only mode, independently of payload data.
    pub(crate) fn native_read_only(&self) -> bool {
        matches!(self.inner.access, Access::NativeReadOnly)
    }
}
