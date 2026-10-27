//! Runs bounded ordinary native reads through existing portable-copy validation.
//!
//! The private filesystem binding cannot initialize, lock, repair or mutate.
//! Native captures accept ordinary directory permissions, including shared 2770
//! ancestors. Their descriptor retention checks data continuity, not Original
//! ownership. All captures and payload bytes are dropped before returning.

mod reads;

use super::{PortableReadLimits, ValidatedPortableBucket, metadata_capabilities};
use crate::{
    bucket::{Access, BucketBinding, FileBucket, FileBucketConfig, Inner, files},
    store::{Clock, ContentValidator, LocalFs, StoreErrorKind, StoreFailure},
};
use reads::ValidationFs;
use std::{path::Component, sync::Arc};
use terrane_format::{
    bucket::{BucketCapabilities, GenerationManifest},
    chunking::ChunkProfile,
    gc::publication::{PortableCurrent, SelectedHistory},
};

/// Validates the complete existing portable closure without activating storage.
///
/// Reads use actual retained nofollow native descriptors and explicit file/count/
/// aggregate budgets. Bindings that decline bounded native capture return
/// `Unsupported`; there is no unbounded or symlink-following fallback. Every
/// consumed file is freshly checked through its original capture before return.
///
/// Only the configured root, profile and locality are used. Publication-control
/// configuration is ignored: protected registration and coordination are never
/// opened, and no lock, create, repair, CAS, probe or durability operation runs.
/// The supplied clock and validator are reused by the existing data validators;
/// this function establishes no host custody or fresh-inventory authority.
///
/// Complete packs are materialized during this bounded validation. The returned
/// metadata snapshot retains no pack bodies or native descriptors and provides
/// neither a live disk reader nor content-serving capability.
///
/// # Errors
/// Returns capacity for exhausted operator budgets; unsupported for unavailable
/// native captures or unknown selected closure; corruption for incompatible
/// profiles, malformed checkpoints, indexes, inventory, content or history; and
/// the actual I/O failure for inaccessible, symlinked, replaced or changed data.
pub async fn validate_existing<F, C, V>(
    mut config: FileBucketConfig,
    fs: &F,
    clock: C,
    validator: V,
    limits: PortableReadLimits,
) -> Result<ValidatedPortableBucket, StoreFailure>
where
    F: LocalFs + BucketBinding,
    C: Clock + BucketBinding,
    V: ContentValidator + BucketBinding,
{
    if !config.root.is_absolute()
        || config
            .root
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        || config.chunk_profile_name != "cdc-1m"
        || config.chunk_profile != ChunkProfile::cdc_1m(config.chunk_profile.seed())
    {
        return Err(files::malformed());
    }
    if limits.max_file_bytes == 0
        || limits.max_input_bytes == 0
        || limits.max_files == 0
        || limits.max_selected_bytes == 0
    {
        return Err(StoreFailure::new(StoreErrorKind::Capacity));
    }
    config.publication_control = None;
    let capabilities = metadata_capabilities(config.locality.clone());
    let io = ValidationFs::new(fs, &config.root, limits);

    // This private value supplies only existing pure/catalog/content validators.
    // It is never opened or exposed. Its filesystem denies every effect, and
    // no public FileBucket method can turn it into a publication capability.
    // The access tag selects layout-two log names in the reused validators;
    // it supplies no working effect path through this read-only binding.
    let bucket = FileBucket {
        inner: Arc::new(Inner {
            config,
            fs: io,
            clock,
            validator,
            capabilities,
            access: Access::Writable,
            #[cfg(all(test, feature = "tokio", unix))]
            content_observation: Arc::default(),
        }),
    };
    let payload = match bucket.portable_copy_payload().await {
        Ok(payload) => payload,
        Err(error) => return Err(bucket.inner.fs.classify(error).await),
    };
    let selected_bytes = payload
        .logical
        .iter()
        .try_fold(0usize, |total, (key, value)| {
            total
                .checked_add(key.len())
                .and_then(|total| total.checked_add(value.as_ref().map_or(0, Vec::len)))
                .ok_or_else(|| StoreFailure::new(StoreErrorKind::Capacity))
        })?;
    if selected_bytes > limits.max_selected_bytes {
        return Err(StoreFailure::new(StoreErrorKind::Capacity));
    }

    // Mutable physical caches do not select data. Decode only the exact pointer
    // already consumed by the same bounded binding and the validated projection.
    let checkpoint = PortableCurrent::decode(&bucket.inner.fs.input("publication/PORTABLE").await?)
        .map_err(|_| files::layout_corrupt())?;
    let selected = |key: &str| {
        payload
            .logical
            .get(key)
            .and_then(Option::as_deref)
            .ok_or_else(files::layout_corrupt)
    };
    let cap = BucketCapabilities::decode(selected("CAPABILITIES")?)
        .map_err(|_| files::layout_corrupt())?;
    let history = SelectedHistory::decode(selected("publication/SELECTED-HISTORY")?)
        .map_err(|_| files::layout_corrupt())?;
    let generation = cap.generation.ok_or_else(files::layout_corrupt)?;
    let manifest =
        GenerationManifest::decode(selected(&format!("objects/index/{generation}/MANIFEST"))?)
            .map_err(|_| files::layout_corrupt())?;

    bucket.inner.fs.close().await?;
    Ok(ValidatedPortableBucket {
        root: bucket.inner.config.root.clone(),
        profile: cap.profile,
        checkpoint,
        selected: payload.logical,
        history,
        manifest,
        capabilities: metadata_capabilities(bucket.inner.config.locality.clone()),
    })
}
