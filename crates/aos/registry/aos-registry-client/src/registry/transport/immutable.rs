//! Bounded phase-major transfer of exact immutable objects to required mirrors.

use std::path::PathBuf;

use anyhow::{Context as _, Result};
use aos_nix_cache::backend::CacheBackend;
use aos_cli_ui::output::Printer;
use futures_util::stream::{StreamExt as _, TryStreamExt as _};

use super::RegistryStorage;

pub use aos_registry_format::publication::pointer_upload_rank;

/// Orders immutable transfers before catalog discovery and receipts.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ImmutableUploadPhase {
    /// Disk payloads required by signed image catalogs.
    ImageDisk,
    /// Content objects and signed catalog metadata.
    Catalog,
    /// Receipts attesting that the preceding immutable inventory is available.
    Receipt,
}

/// Binds one local source to an exact immutable destination identity.
#[derive(Clone, Debug)]
pub struct ImmutableUpload {
    /// Canonical backend-relative destination key.
    pub path: String,
    /// Private local source retaining the exact inventoried bytes.
    pub source: PathBuf,
    /// Lowercase SHA-256 without the algorithm prefix.
    pub sha256: String,
    /// Exact stored byte size.
    pub byte_size: u64,
    /// Publication phase required by this object.
    pub phase: ImmutableUploadPhase,
}

/// Uploads a bounded inventory in phase-major order across every required mirror.
///
/// Matching objects are reused only after actual identity verification. Failed
/// mirrors receive no later phases; every mirror must succeed before readiness
/// can be reported. Backend transfer managers own retry and durable resume.
///
/// # Errors
///
/// Returns an error for invalid sources, byte-count overflow, conflicting objects,
/// unavailable identity evidence, or failed transfers on any required mirror.
pub async fn upload_immutable_inventory(
    objects: &[ImmutableUpload],
    destinations: &[(&str, &dyn CacheBackend)],
    printer: &Printer,
) -> Result<usize> {
    const CONCURRENCY: usize = 16;
    anyhow::ensure!(
        !destinations.is_empty(),
        "immutable upload requires a destination"
    );
    let total = objects
        .iter()
        .try_fold(0_u64, |total, object| {
            total
                .checked_add(object.byte_size)
                .context("immutable upload byte count overflow")
        })?
        .checked_mul(u64::try_from(destinations.len())?)
        .context("mirror byte count overflow")?;
    let progress = printer.transfer("Uploading immutable candidate inventory", total);
    let mut skipped = 0;
    let mut failed = vec![false; destinations.len()];
    let mut failures = Vec::new();
    for phase in [
        ImmutableUploadPhase::ImageDisk,
        ImmutableUploadPhase::Catalog,
        ImmutableUploadPhase::Receipt,
    ] {
        for (index, (name, backend)) in destinations.iter().enumerate() {
            if failed[index] {
                continue;
            }
            let storage = RegistryStorage::new(*backend);
            let results = futures_util::stream::iter(
                objects
                    .iter()
                    .filter(|object| object.phase == phase)
                    .map(|object| {
                        let storage = &storage;
                        let progress = &progress;
                        async move {
                            let matched = storage
                                .object_matches(&object.path, &object.sha256, object.byte_size)
                                .await?;
                            if !matched {
                                storage
                                    .put_object(&object.path, &object.source, &object.sha256)
                                    .await?;
                            }
                            anyhow::ensure!(
                                storage
                                    .object_matches(&object.path, &object.sha256, object.byte_size)
                                    .await?,
                                "mirror did not verify immutable object {}",
                                object.path
                            );
                            progress.inc(object.byte_size);
                            Ok::<_, anyhow::Error>(matched)
                        }
                    }),
            )
            .buffer_unordered(CONCURRENCY)
            .try_collect::<Vec<_>>()
            .await;
            match results {
                Ok(results) => skipped += results.into_iter().filter(|matched| *matched).count(),
                Err(error) => {
                    failed[index] = true;
                    failures.push(format!("{name}: {error:#}"));
                }
            }
        }
    }
    progress.finish();
    anyhow::ensure!(
        failures.is_empty(),
        "immutable candidate upload failed:\n{}",
        failures.join("\n")
    );
    Ok(skipped)
}
