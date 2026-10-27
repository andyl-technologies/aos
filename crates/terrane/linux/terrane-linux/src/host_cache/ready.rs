//! Composes portable bucket validity with actual native recovery and Running custody.
//!
//! Only the asynchronous native opener constructs this value. A decoded ledger,
//! configuration record, portable snapshot or publisher barrier cannot replace
//! its retained physical cache owner. The portable observation stays separate
//! from the owner's authority over native content and accounting.

use super::{
    NativeCacheOwnerConfig, NativeCachePreparation, NativeCacheStartupStage, NativeHostLayout,
    NativeHostMetadataReader, NativeMetadataOwner,
};
use crate::quota_confinement::Installed;
use std::{io, sync::Arc};
use terrane_sdk::{
    bucket::{
        FileBucketConfig,
        portable_reader::{PortableReadLimits, ValidatedPortableBucket, validate_existing},
    },
    host::cache::HostDomainLocation,
    repository::MetadataValidator,
    store::{TokioClock, TokioLocalFs},
};

/// Retains a valid portable bucket and its genuinely recovered running native owner.
///
/// This value owns the exclusive cache-state worker, actual retained layout,
/// bounded verified metadata reader and independently validated portable closure.
/// Its fields are private and it cannot be reconstructed from durable records.
/// Dropping it closes the physical worker using the owner's existing shutdown
/// rules; accepted work retains its original physical resources until completion.
///
/// This is a host-local composition. Guest authorization, ref publication and
/// cross-role service deployment require their own capabilities.
pub struct NativeReady {
    owner: NativeMetadataOwner,
    metadata: NativeHostMetadataReader,
    layout: Arc<NativeHostLayout<HostDomainLocation>>,
    portable: ValidatedPortableBucket,
    portable_config: FileBucketConfig,
    limits: PortableReadLimits,
    max_allocation_bytes: usize,
    max_requests: usize,
    consumer_release_grace: std::time::Duration,
}

impl NativeReady {
    /// Validates the bucket, recovers actual native inventory and acknowledges Resume.
    ///
    /// Both configurations must select the same exact root and chunk profile.
    /// Portable validation runs before cache-state initialization and again after
    /// recovery. The actual native factory authenticates quota, custody and the
    /// publisher's seal probe. Only the resulting owner's genuine completed
    /// recovery can cross its physical Resume turn. A changed portable checkpoint
    /// refuses the open; it never imports a cold epoch as current authority.
    ///
    /// With `surface-fuse` and an explicitly funded surface-index policy, old
    /// kernel references remain draining through the new Resume. Their original
    /// bindings, pins and physical charges remain protected until authenticated
    /// closure; recovery grants no authority to resume the old exposure.
    /// Without that policy, unresolved exposure custody refuses startup.
    ///
    /// The caller installs confinement in its fresh role process before calling
    /// this method, using the same native bootstrap required by cache preparation.
    /// Failures may leave completed recovery effects and must not trigger a
    /// fallback that initializes another bucket or erases retained state.
    ///
    /// # Errors
    /// Returns errors for mismatched configuration, invalid or oversized portable
    /// state, unavailable actual native enforcement, changed roots, concurrent
    /// state ownership, failed recovery or Resume, and an unstable checkpoint.
    pub async fn open(
        config: NativeCacheOwnerConfig,
        portable_config: FileBucketConfig,
        limits: PortableReadLimits,
        confinement: Arc<Installed>,
    ) -> io::Result<Self> {
        Self::open_with_stage(
            config,
            portable_config,
            limits,
            confinement,
            &mut NativeCacheStartupStage::Configuration,
        )
        .await
    }

    /// Observes startup without wrapping or replacing the original native error.
    ///
    /// # Errors
    /// Returns the same validation, custody and recovery failures as the public opener.
    pub(crate) async fn open_with_stage(
        config: NativeCacheOwnerConfig,
        portable_config: FileBucketConfig,
        limits: PortableReadLimits,
        confinement: Arc<Installed>,
        stage: &mut NativeCacheStartupStage,
    ) -> io::Result<Self> {
        *stage = NativeCacheStartupStage::Configuration;
        config.validate()?;
        if portable_config.root != config.location.root()
            || &portable_config.chunk_profile != config.location.chunk_profile()
            || portable_config.chunk_profile_name != config.publisher.chunk_profile_name
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "portable and native owner bindings differ",
            ));
        }
        *stage = NativeCacheStartupStage::Confinement;
        confinement.check_current()?;
        *stage = NativeCacheStartupStage::PortableBeforeRecovery;
        let before = validate(&portable_config, limits).await?;
        let reads = config.reads;
        let max_requests = config.inventory_entries;
        let consumer_release_grace = config.policy.release_grace;
        #[cfg(feature = "surface-fuse")]
        let retain_surface_exposures = config.surface_index.is_some();
        let mut preparation =
            NativeCachePreparation::inspect_with_stage(config, confinement, stage)?;
        *stage = NativeCacheStartupStage::PortableCatalog;
        preparation.bind_portable_catalog(&before)?;
        let layout = Arc::clone(preparation.layout());
        layout.recheck()?;
        *stage = NativeCacheStartupStage::MetadataReader;
        let metadata = NativeHostMetadataReader::open(Arc::clone(&layout), reads)
            .await
            .map_err(io::Error::other)?;

        *stage = NativeCacheStartupStage::OwnerStart;
        let owner = NativeMetadataOwner::start(preparation)?;
        *stage = NativeCacheStartupStage::Recovery;
        #[cfg(feature = "surface-fuse")]
        let completed = if retain_surface_exposures {
            owner.recover_retaining_surface_exposures().await?
        } else {
            owner.recover().await?
        };
        #[cfg(not(feature = "surface-fuse"))]
        let completed = owner.recover().await?;
        *stage = NativeCacheStartupStage::PublisherResume;
        owner
            .resume_recovered(completed)
            .await
            .map_err(io::Error::other)?;

        *stage = NativeCacheStartupStage::PortableAfterRecovery;
        let portable = validate(&portable_config, limits).await?;
        *stage = NativeCacheStartupStage::FinalCustody;
        layout.recheck()?;
        *stage = NativeCacheStartupStage::PortableCheckpoint;
        if before.checkpoint() != portable.checkpoint() {
            return Err(io::Error::other(
                "portable checkpoint changed during native recovery",
            ));
        }
        Ok(Self {
            owner,
            metadata,
            layout,
            portable,
            portable_config,
            limits,
            max_allocation_bytes: reads.max_allocation_bytes,
            max_requests,
            consumer_release_grace,
        })
    }

    /// Supplies scheduling policy only; the physical sweep still proves release.
    pub(super) fn consumer_release_grace(&self) -> std::time::Duration {
        self.consumer_release_grace
    }

    pub(super) fn request_bounds(&self) -> (usize, usize) {
        (self.max_allocation_bytes, self.max_requests)
    }

    pub(super) fn locality(&self) -> &terrane_format::refs::Locality {
        &self.portable_config.locality
    }

    /// Borrows the original running physical owner for content and maintenance work.
    pub fn owner(&self) -> &NativeMetadataOwner {
        &self.owner
    }

    /// Borrows the actual retained domain layout and provisioning guard.
    pub fn layout(&self) -> &Arc<NativeHostLayout<HostDomainLocation>> {
        &self.layout
    }

    /// Borrows the bounded metadata reader tied to the original native layout.
    pub fn metadata(&self) -> &NativeHostMetadataReader {
        &self.metadata
    }

    /// Borrows the portable observation established after actual recovery.
    ///
    /// This point-in-time snapshot is neither ref authority nor proof of later
    /// disk contents. Use [`Self::validate_portable`] for a fresh bounded check.
    pub fn portable_snapshot(&self) -> &ValidatedPortableBucket {
        &self.portable
    }

    /// Revalidates the complete current portable closure under retained native roots.
    ///
    /// Host cache admission and maintenance use registered host prefixes while
    /// the portable bucket retains its ordinary validity. This operation checks
    /// that invariant without opening protected publication-control state.
    ///
    /// # Errors
    /// Returns native root-currentness, portable format, identity, resource-bound
    /// or actual filesystem failures. It never repairs or initializes the bucket.
    pub async fn validate_portable(&self) -> io::Result<ValidatedPortableBucket> {
        self.layout.recheck()?;
        let result = validate(&self.portable_config, self.limits).await?;
        self.layout.recheck()?;
        Ok(result)
    }
}

async fn validate(
    config: &FileBucketConfig,
    limits: PortableReadLimits,
) -> io::Result<ValidatedPortableBucket> {
    validate_existing(
        config.clone(),
        &TokioLocalFs,
        TokioClock,
        MetadataValidator::new(config.chunk_profile.clone()),
        limits,
    )
    .await
    .map_err(io::Error::other)
}
