//! Admits an explicitly requested portable copy through the native factory.
//!
//! Existing payload data never grants registration. The administrative call
//! fixes independently configured ownership, retains the actual destination
//! exclusion and requests a new protected native registration event.

use super::{Access, BucketBinding, FileBucket, FileBucketConfig, Inner, files, publication};
use crate::store::{
    Capabilities, Clock, ContentValidator, Durability, LocalFs, RangeCapability, RefCapability,
    StoreFailure,
};
use std::sync::Arc;
use terrane_format::bucket::BucketKey;
use terrane_format::chunking::ChunkProfile;

impl<F: LocalFs + BucketBinding, C: Clock + BucketBinding, V: ContentValidator + BucketBinding>
    FileBucket<F, C, V>
{
    /// Initializes an explicitly authorized, quiescent portable directory copy.
    ///
    /// The caller acts as the independently configured native operator. This
    /// operation requires an existing destination root and coordination inode,
    /// complete copied payload and selected logs, and a genuinely new external
    /// protected registration. It imports no source lease, lineage, physical
    /// age, deletion authority or signing trust. Ordinary [`Self::open`] keeps
    /// refusing existing unregistered roots; interrupted Pending activation is
    /// recovered through that ordinary opener, never another initialization.
    ///
    /// # Errors
    /// Refuses unsafe or incompatible configuration, missing or corrupt payload,
    /// same-root copies, existing control, unavailable native retention, failed
    /// administrative registration and uncertain staging or activation durability.
    /// Valid legacy Unknown selected history or index visibility refuses complete
    /// activation with `Unsupported`; Unknown burn completeness stays Unknown.
    pub async fn initialize_portable_copy(
        config: FileBucketConfig,
        fs: F,
        clock: C,
        validator: V,
    ) -> Result<Self, StoreFailure> {
        #[cfg(not(unix))]
        {
            let _ = (config, fs, clock, validator);
            Err(StoreFailure::new(crate::store::StoreErrorKind::Unsupported))
        }
        #[cfg(unix)]
        {
            if config.publication_control.is_none()
                || config.chunk_profile_name != "cdc-1m"
                || config.chunk_profile != ChunkProfile::cdc_1m(config.chunk_profile.seed())
            {
                return Err(publication::unsupported());
            }
            let protected = config
                .publication_control
                .as_ref()
                .ok_or_else(publication::unsupported)?;
            let (owner, control) = publication::configured_location(&config.root, protected)?;
            let timestamp = clock
                .now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map_err(|_| files::malformed())?
                .as_secs();
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
                    #[cfg(all(test, feature = "tokio", unix))]
                    content_observation: Arc::default(),
                }),
            };
            let request = crate::store::native_initialization_request(
                bucket.root(),
                &control,
                owner,
                bucket.profile(),
                timestamp,
            )?;
            bucket.check_directory(bucket.root()).await?;
            let key = BucketKey::parse("CAPABILITIES").map_err(|_| files::malformed())?;
            let guard = bucket
                .inner
                .fs
                .lock_existing_exclusive(&bucket.root().join(key.lock_name()))
                .await
                .map_err(files::io_failure)?;
            let retained = bucket
                .inner
                .fs
                .retain_native_exclusion(&guard)
                .map_err(files::io_failure)?;
            let payload = bucket.portable_copy_payload().await?;
            let request =
                crate::store::native_publication_effects::initialization_inputs::request_for_copy(
                    request, payload, retained,
                )?;
            let initialization = bucket.inner.fs.initialize_publication(request).await?;
            bucket.open_publication(initialization).await?;
            drop(guard);
            let checked = bucket.existing_exclusive().await?;
            bucket.catalog().await?;
            drop(checked);
            Ok(bucket)
        }
    }
}
