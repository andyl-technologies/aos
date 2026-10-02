//! Stages exact immutable static-origin inventories across every mirror.

use std::io::Read as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use aos_cache::backend::{self, AuthOptions, CacheBackend};
use aos_core::output::Printer;
use sha2::{Digest as _, Sha256};

use super::static_upload::{
    StaticOriginClass, StaticOriginFile, StaticOriginUploadReport, collect_static_origin_files,
};

/// Uploads only immutable origin bytes, with exact identity checks on every mirror.
///
/// Public pack indexes, listings, registry refs, and channel pointers remain
/// withheld. All mirrors receive disk payloads before any receives catalog
/// objects, preserving the full publication's phase ordering. Matching objects
/// are reused only after their actual SHA-256 and size have been verified.
///
/// # Errors
///
/// Returns an error for invalid sources, connection failures, or any transfer
/// or inventory verification failure on a required destination.
pub async fn stage_static_origin_to_all(
    registry_dir: &Path,
    upload_urls: &[String],
    auth: &AuthOptions,
    printer: &Printer,
) -> Result<StaticOriginUploadReport> {
    anyhow::ensure!(
        !upload_urls.is_empty(),
        "at least one upload URL is required"
    );
    let mut files = collect_static_origin_files(registry_dir)?;
    files.retain(|file| {
        matches!(
            file.class,
            StaticOriginClass::ImageDisk
                | StaticOriginClass::Immutable
                | StaticOriginClass::Receipt
        ) && !aos_registry_surface::keymap::is_mutable_path(&file.relative_path)
    });
    for file in &mut files {
        bind_identity(file)?;
    }
    let bytes = files.iter().try_fold(0_u64, |total, file| {
        total
            .checked_add(file.byte_size.context("stage object has no exact size")?)
            .context("staged upload total overflow")
    })?;
    let mut destinations: Vec<(&str, Box<dyn CacheBackend>)> = Vec::new();
    for url in upload_urls {
        destinations.push((url, backend::from_url(url, auth).await?));
    }
    let mut snapshots = Vec::new();
    let mut objects = Vec::new();
    for file in &files {
        let sha256 = file
            .sha256
            .as_deref()
            .context("stage object has no SHA-256")?;
        let size = file.byte_size.context("stage object has no size")?;
        let snapshot = super::static_upload::snapshot_local_delivery_object(file, size, sha256)?
            .into_temp_path();
        objects.push(super::transport::ImmutableUpload {
            path: file.relative_path.clone(),
            source: snapshot.to_path_buf(),
            sha256: sha256.to_owned(),
            byte_size: size,
            phase: match file.class {
                StaticOriginClass::ImageDisk => super::transport::ImmutableUploadPhase::ImageDisk,
                StaticOriginClass::Receipt => super::transport::ImmutableUploadPhase::Receipt,
                _ => super::transport::ImmutableUploadPhase::Catalog,
            },
        });
        snapshots.push(snapshot);
    }
    let mirrors = destinations
        .iter()
        .map(|(name, backend)| (*name, backend.as_ref()))
        .collect::<Vec<_>>();
    let skipped_files =
        super::transport::upload_immutable_inventory(&objects, &mirrors, printer).await?;
    Ok(StaticOriginUploadReport {
        files: files.len(),
        bytes,
        skipped_files,
    })
}

fn bind_identity(file: &mut StaticOriginFile) -> Result<()> {
    let descriptor = rustix::fs::open(
        &file.source,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC | rustix::fs::OFlags::NOFOLLOW,
        rustix::fs::Mode::empty(),
    )?;
    let mut source = std::fs::File::from(descriptor);
    let metadata = source.metadata()?;
    anyhow::ensure!(metadata.is_file(), "draft inventory contains a non-file");
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
        size = size
            .checked_add(u64::try_from(count)?)
            .context("stage object size overflow")?;
    }
    let sha256 = hex::encode(digest.finalize());
    anyhow::ensure!(
        size == metadata.len()
            && file.byte_size.is_none_or(|expected| expected == size)
            && file
                .sha256
                .as_ref()
                .is_none_or(|expected| expected == &sha256),
        "draft object changed or differs from signed identity: {}",
        file.relative_path
    );
    file.byte_size = Some(size);
    file.sha256 = Some(sha256);
    Ok(())
}
