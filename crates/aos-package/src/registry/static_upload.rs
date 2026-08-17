//! Static git-origin upload helpers.
//!
//! This uploads the dumb-HTTP git origin surface in producer-safe,
//! *phase-major* order across all destinations: every
//! [`StaticOriginClass::ImageDisk`] payload is uploaded to every destination
//! first, followed by [`StaticOriginClass::Immutable`] Git/catalog payloads,
//! then a [`StaticOriginClass::Receipt`] transaction marker, and only then are
//! [`StaticOriginClass::Mutable`] pointers (`HEAD`, `info/refs`, channel
//! partitions) uploaded. Mutable publication begins only when every required
//! destination completed every payload and receipt phase; otherwise all
//! destinations retain their prior pointers.
//!
//! The resulting invariant: any pointer visible on any mirror only
//! references objects present on every mirror that completed the
//! immutable phase. A consumer racing a partially completed upload can
//! therefore at worst see *old* pointers — never a pointer to content
//! that has not been uploaded yet, on any mirror.
//!
//! Within each phase the per-destination uploads run concurrently
//! (`UPLOAD_CONCURRENCY` in flight), and an already-present immutable object
//! Git immutables may be skipped by existence (unless `--no-skip`). Image and
//! receipt objects are always PUT with their exact SHA-256 metadata so an
//! existence-only answer can never advance the publication transaction.
//!
//! Every file is classified as [`StaticOriginClass::ImageDisk`] (direct disk
//! bytes), [`StaticOriginClass::Immutable`] (content-addressed Git objects,
//! signed metadata, and release packs), [`StaticOriginClass::Receipt`] (the
//! commit-scoped publication transaction marker), or
//! [`StaticOriginClass::Mutable`] (refs, channel partitions, server-info
//! metadata) and tagged with matching `Cache-Control` and `Content-Type`
//! headers for CDN-fronted hosting. The static binary cache (narinfos, NARs,
//! `nix-cache-info`) is uploaded separately, and owns its own §8 write
//! ordering, in [`crate::registry::nixcache::upload_static_cache_to_all`].

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_cache::backend::{
    self, AuthOptions, CacheBackend, IMMUTABLE_CACHE_CONTROL, MUTABLE_CACHE_CONTROL,
};
use aos_core::output::Printer;
use futures_util::stream::{StreamExt, TryStreamExt};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::registry::objectstore;

/// Maximum origin-file uploads kept in flight per destination. The
/// `aos_net` connection pool enforces the real per-host limit; this only
/// bounds how many requests we stage at once.
const UPLOAD_CONCURRENCY: usize = 16;

/// Mutability class of a static origin file.
///
/// The `Ord` impl encodes the safe transaction order: disk bytes, signed
/// metadata, receipt, then mutable pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StaticOriginClass {
    /// Content-addressed disk-image bytes, published before the signed catalog.
    ImageDisk,
    /// Content-addressed payload (git objects and release packs).
    Immutable,
    /// Durable marker proving both immutable phases completed for one commit.
    Receipt,
    /// Pointer or metadata rewritten on publish (`HEAD`, `info/refs`,
    /// `objects/info/*`, channel partitions).
    Mutable,
}

/// One file of the static origin surface, ready for upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticOriginFile {
    /// Path of the file relative to the origin root, `/`-separated.
    pub relative_path: String,
    /// Local filesystem path the bytes are read from.
    pub source: PathBuf,
    /// Mutability class that determined ordering and cache headers.
    pub class: StaticOriginClass,
    /// `Content-Type` header to serve the file with.
    pub content_type: &'static str,
    /// `Cache-Control` header to serve the file with.
    pub cache_control: &'static str,
    /// Attachment header persisted by CDN-capable object stores.
    pub content_disposition: Option<String>,
    /// Lowercase SHA-256 persisted as object integrity metadata.
    pub sha256: Option<String>,
    /// Exact expected byte length for content-bound files.
    pub byte_size: Option<u64>,
}

/// Summary of a completed static origin upload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticOriginUploadReport {
    /// Number of files uploaded per destination.
    pub files: usize,
    /// Total payload size in bytes per destination.
    pub bytes: u64,
    /// Number of immutable files skipped because a destination already had
    /// the backend-relative object.
    pub skipped_files: usize,
}

/// Collect the git-origin file set in safe upload order.
///
/// Walks the registry's git directory (`HEAD`, `info/refs`, `objects/`,
/// `releases/`, `channels/`) plus its descriptor-pinned
/// `aos-image-staging/images/` area, classifies each file, and sorts
/// phase-first then by path. Disk images never enter Git objects or packs.
/// Missing optional directories are skipped. The static binary cache is
/// uploaded separately (see the module docs).
///
/// # Errors
///
/// Returns an error if the git directory cannot be resolved, a directory
/// cannot be read, or a file path contains non-UTF-8 or unsafe components.
pub fn collect_static_origin_files(registry_dir: &Path) -> Result<Vec<StaticOriginFile>> {
    let git_dir = objectstore::repo_git_dir(registry_dir)?;
    let mut files = Vec::new();

    push_file(&mut files, &git_dir, "HEAD", StaticOriginClass::Mutable)?;
    push_file(
        &mut files,
        &git_dir,
        "info/refs",
        StaticOriginClass::Mutable,
    )?;
    push_dir(&mut files, &git_dir, "objects", classify_git_path)?;
    push_dir(&mut files, &git_dir, "releases", classify_release_path)?;
    push_dir(
        &mut files,
        &git_dir.join("aos-image-staging"),
        "images",
        |path| {
            if path.ends_with("image-info.json") {
                Ok(StaticOriginClass::Immutable)
            } else {
                Ok(StaticOriginClass::ImageDisk)
            }
        },
    )?;
    push_dir(&mut files, &git_dir, "channels", |_| {
        Ok(StaticOriginClass::Mutable)
    })?;
    push_dir(
        &mut files,
        &git_dir.join("aos-static-origin"),
        "publication-receipts",
        |_| Ok(StaticOriginClass::Receipt),
    )?;
    if files.iter().any(|file| {
        matches!(
            file.class,
            StaticOriginClass::ImageDisk | StaticOriginClass::Receipt
        )
    }) {
        let repository = git2::Repository::open(registry_dir)
            .or_else(|_| git2::Repository::open_bare(&git_dir))
            .context("opening static origin to resolve its publication commit")?;
        let commit = repository
            .head()
            .context("reading static origin HEAD")?
            .peel_to_commit()
            .context("resolving static origin publication commit")?
            .id();
        let required = format!("publication-receipts/{commit}.json");
        if let Some(receipt) = files
            .iter()
            .find(|file| file.class == StaticOriginClass::Receipt && file.relative_path == required)
            .cloned()
        {
            add_receipt_image_objects(&mut files, &git_dir, commit, &receipt)?;
        } else {
            bail!("published image catalog has no durable receipt for current commit {commit}");
        }
    }

    files.sort_by(|a, b| {
        a.class
            .cmp(&b.class)
            .then_with(|| a.relative_path.cmp(&b.relative_path))
    });
    Ok(files)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImagePublicationReceipt {
    schema_version: u32,
    commit: String,
    registry: String,
    catalog_digest: String,
    objects: Vec<ImagePublicationReceiptObject>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImagePublicationReceiptObject {
    key: String,
    role: String,
    byte_size: u64,
    sha256: String,
}

fn add_receipt_image_objects(
    files: &mut Vec<StaticOriginFile>,
    git_dir: &Path,
    commit: git2::Oid,
    receipt_file: &StaticOriginFile,
) -> Result<()> {
    let bytes =
        std::fs::read(&receipt_file.source).context("reading current image publication receipt")?;
    if bytes.len() > 1024 * 1024 {
        bail!("image publication receipt exceeds the 1 MiB producer limit");
    }
    let receipt: ImagePublicationReceipt =
        serde_json::from_slice(&bytes).context("parsing current image publication receipt")?;
    if receipt.schema_version != 1 || receipt.commit != commit.to_string() {
        bail!("image publication receipt does not match current commit");
    }
    let mut digest_objects = Vec::with_capacity(receipt.objects.len());
    let mut seen = std::collections::BTreeSet::new();
    for object in &receipt.objects {
        if object.byte_size == 0 || !seen.insert(object.key.clone()) {
            bail!("image publication receipt contains an invalid or repeated object");
        }
        let path_digest = image_sha256(&object.key)?
            .context("image publication receipt contains a non-canonical object key")?;
        if path_digest != object.sha256 {
            bail!("image publication receipt object key and SHA-256 disagree");
        }
        let class = match object.role.as_str() {
            "disk" => StaticOriginClass::ImageDisk,
            "image-info" => StaticOriginClass::Immutable,
            _ => bail!("image publication receipt contains an unknown object role"),
        };
        digest_objects.push((
            object.key.as_str(),
            object.role.as_str(),
            object.byte_size,
            object.sha256.as_str(),
        ));
        if let Some(file) = files
            .iter_mut()
            .find(|file| file.relative_path == object.key)
        {
            file.class = class;
            file.sha256 = Some(object.sha256.clone());
            file.byte_size = Some(object.byte_size);
        } else {
            files.push(StaticOriginFile {
                relative_path: object.key.clone(),
                source: git_dir.join("aos-image-staging").join(&object.key),
                class,
                content_type: content_type(&object.key),
                cache_control: cache_control(class),
                content_disposition: image_content_disposition(&object.key)?,
                sha256: Some(object.sha256.clone()),
                byte_size: Some(object.byte_size),
            });
        }
    }
    let digest =
        aos_registry_surface::manifest::image_catalog_digest(&receipt.registry, digest_objects);
    if digest != receipt.catalog_digest {
        bail!("image publication receipt catalog digest is invalid");
    }
    Ok(())
}

/// Upload the static origin surface to every destination URL in
/// phase-major order.
///
/// Disk bytes are uploaded to every destination first. Git objects, the signed
/// catalog, and per-format metadata follow only on destinations whose disk
/// phase succeeded. A durable receipt follows both payload phases. Mutable
/// refs/channels move last only after every required destination has accepted
/// every receipt. A failed destination leaves all destinations' pointers stale
/// but consistent; retrying is idempotent.
///
/// Destinations are attempted independently: a failure on one does not
/// stop uploads to the others.
///
/// # Errors
///
/// Returns an error when no upload URL is given, the origin has no files,
/// a source file cannot be stat'ed, or any destination fails in either
/// phase (the error aggregates all per-destination failures, including
/// those whose mutable phase was skipped).
pub async fn upload_static_origin_to_all(
    registry_dir: &Path,
    upload_urls: &[String],
    auth: &AuthOptions,
    no_skip: bool,
    printer: &Printer,
) -> Result<StaticOriginUploadReport> {
    if upload_urls.is_empty() {
        bail!("at least one upload URL is required");
    }

    let files = collect_static_origin_files(registry_dir)?;
    if files.is_empty() {
        bail!("static origin has no files to upload");
    }

    let bytes = total_bytes(&files)?;
    let report = StaticOriginUploadReport {
        files: files.len(),
        bytes,
        skipped_files: 0,
    };
    // Connect every destination first; a connect failure is a per-destination
    // failure that excludes that mirror from both phases.
    let mut failures = Vec::new();
    let mut destinations: Vec<(&str, Box<dyn CacheBackend>)> = Vec::new();
    for upload_url in upload_urls {
        match backend::from_url(upload_url, auth).await {
            Ok(backend) => destinations.push((upload_url.as_str(), backend)),
            Err(err) => failures.push(format!("{upload_url}: {err:#}")),
        }
    }

    let all_destinations_connected = failures.is_empty();
    let (phase_failures, skipped_files) = upload_phase_major(
        &files,
        &destinations,
        no_skip,
        all_destinations_connected,
        printer,
    )
    .await;
    failures.extend(phase_failures);

    if !failures.is_empty() {
        bail!(
            "static origin upload failed for {}/{} destination(s):\n{}",
            failures.len(),
            upload_urls.len(),
            failures.join("\n")
        );
    }

    Ok(StaticOriginUploadReport {
        skipped_files,
        ..report
    })
}

/// Upload `files` to already-connected destinations in phase-major order.
///
/// Phase 1 uploads every [`StaticOriginClass::ImageDisk`] file to every
/// destination. Phase 2 uploads Git/catalog [`StaticOriginClass::Immutable`]
/// files only where the disk phase succeeded. Phase 3 uploads the durable
/// [`StaticOriginClass::Receipt`] only where both payload phases succeeded.
/// Phase 4 uploads [`StaticOriginClass::Mutable`] pointers only where the
/// receipt succeeded. Within a phase, each destination's files upload concurrently
/// (`UPLOAD_CONCURRENCY` in flight), and an already-present immutable object is
/// skipped unless `no_skip` is set. Exact image and receipt objects are never
/// skipped by existence alone.
///
/// Returns the per-destination failure messages (empty when every destination
/// completed both phases) and the total number of skipped (already-present)
/// uploads across all destinations.
async fn upload_phase_major(
    files: &[StaticOriginFile],
    destinations: &[(&str, Box<dyn CacheBackend>)],
    no_skip: bool,
    all_destinations_ready: bool,
    printer: &Printer,
) -> (Vec<String>, usize) {
    let mut failures = Vec::new();
    let mut skipped_files = 0usize;
    let mut immutable_ok = vec![true; destinations.len()];

    for (index, (upload_url, backend)) in destinations.iter().enumerate() {
        match upload_class(
            backend.as_ref(),
            files,
            StaticOriginClass::ImageDisk,
            no_skip,
        )
        .await
        {
            Ok(skipped) => {
                skipped_files += skipped;
            }
            Err(err) => {
                failures.push(format!("{upload_url}: {err:#}"));
                immutable_ok[index] = false;
            }
        }
    }

    for (index, (upload_url, backend)) in destinations.iter().enumerate() {
        if !immutable_ok[index] {
            continue;
        }
        match upload_class(
            backend.as_ref(),
            files,
            StaticOriginClass::Immutable,
            no_skip,
        )
        .await
        {
            Ok(skipped) => skipped_files += skipped,
            Err(err) => {
                failures.push(format!("{upload_url}: {err:#}"));
                immutable_ok[index] = false;
            }
        }
    }

    for (index, (upload_url, backend)) in destinations.iter().enumerate() {
        if !immutable_ok[index] {
            continue;
        }
        match upload_class(backend.as_ref(), files, StaticOriginClass::Receipt, no_skip).await {
            Ok(skipped) => skipped_files += skipped,
            Err(err) => {
                failures.push(format!("{upload_url}: {err:#}"));
                immutable_ok[index] = false;
            }
        }
    }

    if !all_destinations_ready || immutable_ok.iter().any(|ready| !ready) {
        for (upload_url, _) in destinations {
            printer.warning(&format!(
                "Skipping mutable pointer upload to {upload_url}: not every required destination completed the receipt phase"
            ));
        }
        return (failures, skipped_files);
    }

    for ((upload_url, backend), ok) in destinations.iter().zip(immutable_ok) {
        if !ok {
            printer.warning(&format!(
                "Skipping mutable pointer upload to {upload_url}: immutable phase failed \
                 (destination left stale but consistent)"
            ));
            continue;
        }
        match upload_class(backend.as_ref(), files, StaticOriginClass::Mutable, no_skip).await {
            Ok(_) => printer.success(&format!(
                "Uploaded static registry origin files to {upload_url}"
            )),
            Err(err) => failures.push(format!("{upload_url}: {err:#}")),
        }
    }

    (failures, skipped_files)
}

/// Upload every file of one mutability class to a single backend, concurrently
/// (`UPLOAD_CONCURRENCY` in flight).
///
/// An already-present Git immutable may be skipped via an existence check
/// (unless `no_skip`). Exact image and receipt objects are always uploaded.
/// Returns the count of skipped files; errors on the first failed upload.
async fn upload_class(
    backend: &dyn CacheBackend,
    files: &[StaticOriginFile],
    class: StaticOriginClass,
    no_skip: bool,
) -> Result<usize> {
    let results = futures_util::stream::iter(files.iter().filter(|file| file.class == class).map(
        |file| async move {
            if file.relative_path.starts_with("images/") {
                let expected_sha256 = file
                    .sha256
                    .as_deref()
                    .context("image delivery object has no signed SHA-256")?;
                let expected_size = file
                    .byte_size
                    .context("image delivery object has no signed byte size")?;
                if backend
                    .static_file_identity(&file.relative_path)
                    .await?
                    .is_some_and(|identity| {
                        identity.byte_size == expected_size && identity.sha256 == expected_sha256
                    })
                {
                    return Ok::<bool, anyhow::Error>(true);
                }
                let snapshot =
                    snapshot_local_delivery_object(file, expected_size, expected_sha256)?;
                backend
                    .put_static_file(
                        &file.relative_path,
                        snapshot.path(),
                        Some(file.content_type),
                        Some(file.cache_control),
                        file.content_disposition.as_deref(),
                        Some(expected_sha256),
                    )
                    .await
                    .with_context(|| format!("uploading {}", file.relative_path))?;
                return Ok::<bool, anyhow::Error>(false);
            }
            if !no_skip
                && file.class == StaticOriginClass::Immutable
                && file.sha256.is_none()
                && backend.exists(&file.relative_path).await?
            {
                return Ok::<bool, anyhow::Error>(true);
            }
            backend
                .put_static_file(
                    &file.relative_path,
                    &file.source,
                    Some(file.content_type),
                    Some(file.cache_control),
                    file.content_disposition.as_deref(),
                    file.sha256.as_deref(),
                )
                .await
                .with_context(|| format!("uploading {}", file.relative_path))?;
            Ok::<bool, anyhow::Error>(false)
        },
    ))
    .buffer_unordered(UPLOAD_CONCURRENCY)
    .try_collect::<Vec<bool>>()
    .await?;
    Ok(results.into_iter().filter(|skipped| *skipped).count())
}

fn snapshot_local_delivery_object(
    file: &StaticOriginFile,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<tempfile::NamedTempFile> {
    let before = std::fs::symlink_metadata(&file.source)
        .with_context(|| format!("stat staged image object {}", file.source.display()))?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() != expected_size {
        bail!(
            "staged image object '{}' is absent or does not match signed size",
            file.relative_path
        );
    }
    let mut source = std::fs::File::open(&file.source)
        .with_context(|| format!("opening staged image object {}", file.source.display()))?;
    let opened = source
        .metadata()
        .with_context(|| format!("stat opened staged image object {}", file.source.display()))?;
    if opened.len() != before.len() || opened.modified().ok() != before.modified().ok() {
        bail!(
            "staged image object '{}' changed while it was opened",
            file.relative_path
        );
    }
    let mut snapshot = tempfile::NamedTempFile::new()
        .context("creating descriptor-stable image upload snapshot")?;
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 128 * 1024];
    loop {
        let count = std::io::Read::read(&mut source, &mut buffer)
            .with_context(|| format!("reading staged image object {}", file.source.display()))?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(count as u64)
            .context("staged image object size overflowed")?;
        if observed > expected_size {
            bail!(
                "staged image object '{}' exceeded signed size",
                file.relative_path
            );
        }
        hasher.update(&buffer[..count]);
        std::io::Write::write_all(&mut snapshot, &buffer[..count])
            .context("writing descriptor-stable image upload snapshot")?;
    }
    let after = source
        .metadata()
        .with_context(|| format!("restat staged image object {}", file.source.display()))?;
    if observed != expected_size
        || after.len() != before.len()
        || after.modified().ok() != before.modified().ok()
        || hex::encode(hasher.finalize()) != expected_sha256
    {
        bail!(
            "staged image object '{}' changed or does not match signed identity",
            file.relative_path
        );
    }
    std::io::Write::flush(&mut snapshot)
        .context("flushing descriptor-stable image upload snapshot")?;
    Ok(snapshot)
}

/// Sum the on-disk size of every collected file.
fn total_bytes(files: &[StaticOriginFile]) -> Result<u64> {
    let mut bytes = 0u64;
    for file in files {
        bytes += match std::fs::metadata(&file.source) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => file
                .byte_size
                .context("missing static-origin source has no signed byte size")?,
            Err(error) => {
                return Err(error).with_context(|| format!("stat {}", file.source.display()));
            }
        };
    }
    Ok(bytes)
}

/// Add a single optional file under `root`; missing files are skipped.
fn push_file(
    files: &mut Vec<StaticOriginFile>,
    root: &Path,
    relative_path: &str,
    class: StaticOriginClass,
) -> Result<()> {
    let source = root.join(relative_path);
    if source.is_file() {
        push_source(files, root, source, class)?;
    }
    Ok(())
}

/// Recursively add every file under `root/relative_dir`, classifying each
/// path with `classify`; a missing directory is skipped.
fn push_dir<F>(
    files: &mut Vec<StaticOriginFile>,
    root: &Path,
    relative_dir: &str,
    classify: F,
) -> Result<()>
where
    F: Fn(&str) -> Result<StaticOriginClass> + Copy,
{
    let dir = root.join(relative_dir);
    if !dir.exists() {
        return Ok(());
    }
    collect_dir(files, root, &dir, classify)
}

fn collect_dir<F>(
    files: &mut Vec<StaticOriginFile>,
    root: &Path,
    dir: &Path,
    classify: F,
) -> Result<()>
where
    F: Fn(&str) -> Result<StaticOriginClass> + Copy,
{
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_dir(files, root, &path, classify)?;
        } else if path.is_file() {
            let relative_path = relative_path(root, &path)?;
            let class = classify(&relative_path)?;
            files.push(StaticOriginFile {
                content_type: content_type(&relative_path),
                cache_control: cache_control(class),
                content_disposition: image_content_disposition(&relative_path)?,
                sha256: static_sha256(&relative_path, &path)?,
                byte_size: Some(std::fs::metadata(&path)?.len()),
                relative_path,
                source: path,
                class,
            });
        }
    }
    Ok(())
}

/// Append one source file with its derived metadata to the file list.
fn push_source(
    files: &mut Vec<StaticOriginFile>,
    root: &Path,
    source: PathBuf,
    class: StaticOriginClass,
) -> Result<()> {
    let relative_path = relative_path(root, &source)?;
    files.push(StaticOriginFile {
        content_type: content_type(&relative_path),
        cache_control: cache_control(class),
        content_disposition: image_content_disposition(&relative_path)?,
        sha256: static_sha256(&relative_path, &source)?,
        byte_size: Some(std::fs::metadata(&source)?.len()),
        relative_path,
        source,
        class,
    });
    Ok(())
}

/// Classify a path under `objects/` using the delivery contract.
///
/// Loose Git paths identify the decompressed object, not its zlib bytes, so a
/// canonical wire encoding may replace an older equivalent representation.
/// Packs remain byte-addressed immutable payloads.
fn classify_git_path(relative_path: &str) -> Result<StaticOriginClass> {
    if aos_registry_surface::keymap::cache_control(relative_path)
        == aos_registry_surface::keymap::MUTABLE_CACHE_CONTROL
    {
        Ok(StaticOriginClass::Mutable)
    } else {
        Ok(StaticOriginClass::Immutable)
    }
}

/// Classify a path under `releases/`: pack payloads are immutable, while each
/// release object store's `info/*` files are replaceable pack indexes.
fn classify_release_path(relative_path: &str) -> Result<StaticOriginClass> {
    if aos_registry_surface::keymap::cache_control(relative_path)
        == aos_registry_surface::keymap::MUTABLE_CACHE_CONTROL
    {
        Ok(StaticOriginClass::Mutable)
    } else {
        Ok(StaticOriginClass::Immutable)
    }
}

/// Render `path` relative to `root` as a `/`-joined string, rejecting
/// non-UTF-8, `..`, and other unsafe components.
fn relative_path(root: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(root)
        .with_context(|| format!("{} is not under {}", path.display(), root.display()))?;
    let mut parts = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .ok_or_else(|| anyhow::anyhow!("path is not UTF-8: {}", path.display()))?;
                if part.is_empty() || part == "." || part == ".." || part.contains('\\') {
                    bail!("unsafe static-origin path component '{part}'");
                }
                parts.push(part);
            }
            _ => bail!("unsafe static-origin path: {}", path.display()),
        }
    }
    Ok(parts.join("/"))
}

/// Map a mutability class to its `Cache-Control` header value.
fn cache_control(class: StaticOriginClass) -> &'static str {
    match class {
        StaticOriginClass::ImageDisk
        | StaticOriginClass::Immutable
        | StaticOriginClass::Receipt => IMMUTABLE_CACHE_CONTROL,
        StaticOriginClass::Mutable => MUTABLE_CACHE_CONTROL,
    }
}

/// Pick a `Content-Type` for a git-origin path by name and extension.
fn content_type(relative_path: &str) -> &'static str {
    if relative_path == "HEAD"
        || relative_path == "info/refs"
        || relative_path.starts_with("objects/info/")
        || (relative_path.starts_with("releases/")
            && aos_registry_surface::keymap::cache_control(relative_path)
                == aos_registry_surface::keymap::MUTABLE_CACHE_CONTROL)
    {
        "text/plain"
    } else if relative_path.ends_with(".pack") {
        "application/x-git-packed-objects"
    } else if relative_path.ends_with(".idx") {
        "application/x-git-packed-objects-toc"
    } else if relative_path.starts_with("images/") && relative_path.ends_with(".img.zst") {
        "application/vnd.aos.disk-image.raw+zstd"
    } else if relative_path.ends_with(".zst") {
        "application/zstd"
    } else if relative_path.ends_with(".wasm") {
        "application/wasm"
    } else if relative_path.ends_with(".html") {
        "text/html; charset=utf-8"
    } else if relative_path.ends_with(".js") {
        "text/javascript"
    } else if relative_path.ends_with(".css") {
        "text/css"
    } else if relative_path.starts_with("images/") && relative_path.ends_with("image-info.json") {
        "application/vnd.aos.image-info+json"
    } else if relative_path.starts_with("images/") && relative_path.ends_with(".qcow2") {
        "application/vnd.aos.disk-image.qcow2"
    } else if relative_path.starts_with("images/") && relative_path.ends_with(".vmdk") {
        "application/x-vmdk"
    } else if relative_path.starts_with("images/") && relative_path.ends_with(".vhd") {
        "application/vnd.aos.disk-image.vhd"
    } else if relative_path.starts_with("publication-receipts/") && relative_path.ends_with(".json")
    {
        "application/vnd.aos.image-publication-receipt+json"
    } else if relative_path.ends_with(".json") {
        "application/json"
    } else {
        "application/octet-stream"
    }
}

fn image_sha256(relative_path: &str) -> Result<Option<String>> {
    let Some(rest) = relative_path.strip_prefix("images/sha256/") else {
        return Ok(None);
    };
    let parts = rest.split('/').collect::<Vec<_>>();
    let digest = match parts.as_slice() {
        [image, _filename] => *image,
        [_image, "metadata", info, "image-info.json"] => *info,
        _ => bail!("non-canonical immutable image object path '{relative_path}'"),
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("invalid SHA-256 in immutable image object path '{relative_path}'");
    }
    Ok(Some(digest.to_string()))
}

fn static_sha256(relative_path: &str, source: &Path) -> Result<Option<String>> {
    if let Some(digest) = image_sha256(relative_path)? {
        return Ok(Some(digest));
    }
    if relative_path.starts_with("publication-receipts/") {
        let bytes = std::fs::read(source)
            .with_context(|| format!("reading publication receipt {}", source.display()))?;
        return Ok(Some(hex::encode(Sha256::digest(bytes))));
    }
    Ok(None)
}

fn image_content_disposition(relative_path: &str) -> Result<Option<String>> {
    if !relative_path.starts_with("images/") {
        return Ok(None);
    }
    let filename = relative_path
        .rsplit('/')
        .next()
        .context("image object path has no filename")?;
    if filename.is_empty()
        || !filename.is_ascii()
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || filename.contains("..")
    {
        bail!("unsafe immutable image filename '{filename}'");
    }
    Ok(Some(format!("attachment; filename=\"{filename}\"")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_LOOSE_OBJECT_PATH: &str =
        "objects/ab/cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    #[test]
    fn image_upload_snapshot_rejects_same_size_corruption_and_pins_verified_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("aos-test.img.zst");
        let good = b"signed-image";
        let corrupt = b"evil--image-";
        assert_eq!(good.len(), corrupt.len());
        std::fs::write(&source, good).unwrap();
        let expected_sha256 = hex::encode(Sha256::digest(good));
        let file = StaticOriginFile {
            relative_path: format!("images/sha256/{expected_sha256}/aos-test.img.zst"),
            source: source.clone(),
            class: StaticOriginClass::ImageDisk,
            content_type: "application/vnd.aos.disk-image.raw+zstd",
            cache_control: IMMUTABLE_CACHE_CONTROL,
            content_disposition: Some("attachment; filename=\"aos-test.img.zst\"".into()),
            sha256: Some(expected_sha256.clone()),
            byte_size: Some(good.len() as u64),
        };

        let snapshot =
            snapshot_local_delivery_object(&file, good.len() as u64, &expected_sha256).unwrap();
        std::fs::write(&source, corrupt).unwrap();
        assert_eq!(std::fs::read(snapshot.path()).unwrap(), good);
        assert!(
            snapshot_local_delivery_object(&file, good.len() as u64, &expected_sha256).is_err(),
            "same-size source corruption must not satisfy the signed digest"
        );
    }

    #[test]
    fn static_origin_files_are_ordered_immutable_before_mutable() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);

        let files = collect_static_origin_files(&root).unwrap();
        let paths = files
            .iter()
            .map(|file| (file.relative_path.as_str(), file.class))
            .collect::<Vec<_>>();

        assert!(paths.contains(&("objects/aa/object", StaticOriginClass::Immutable)));
        assert!(paths.contains(&(TEST_LOOSE_OBJECT_PATH, StaticOriginClass::Mutable)));
        assert!(paths.contains(&(
            "releases/1/0/0/objects/pack/pack-demo.pack",
            StaticOriginClass::Immutable
        )));
        assert!(paths.contains(&(
            "releases/1/0/0/objects/info/packs",
            StaticOriginClass::Mutable
        )));
        let disk_path = files
            .iter()
            .find(|file| file.class == StaticOriginClass::ImageDisk)
            .unwrap()
            .relative_path
            .clone();
        assert!(paths.contains(&(disk_path.as_str(), StaticOriginClass::ImageDisk)));
        let receipt_path = files
            .iter()
            .find(|file| file.class == StaticOriginClass::Receipt)
            .unwrap()
            .relative_path
            .clone();
        assert!(paths.contains(&(receipt_path.as_str(), StaticOriginClass::Receipt)));
        assert!(paths.contains(&("HEAD", StaticOriginClass::Mutable)));
        assert!(paths.contains(&("info/refs", StaticOriginClass::Mutable)));
        assert!(paths.contains(&("objects/info/alternates", StaticOriginClass::Mutable)));
        assert!(paths.contains(&("channels/stable/00", StaticOriginClass::Mutable)));

        let pos = |needle: &str| {
            files
                .iter()
                .position(|file| file.relative_path == needle)
                .unwrap_or_else(|| panic!("missing {needle}"))
        };
        assert!(pos("objects/aa/object") < pos("HEAD"));
        assert!(pos(&disk_path) < pos("HEAD"));
        assert!(pos(&receipt_path) < pos("HEAD"));
        assert!(pos("releases/1/0/0/objects/pack/pack-demo.pack") < pos("objects/info/alternates"));
    }

    #[test]
    fn static_origin_files_carry_cdn_cache_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);

        let files = collect_static_origin_files(&root).unwrap();
        assert_static_metadata(&files, "HEAD", "text/plain", MUTABLE_CACHE_CONTROL);
        assert_static_metadata(&files, "info/refs", "text/plain", MUTABLE_CACHE_CONTROL);
        assert_static_metadata(
            &files,
            "objects/info/alternates",
            "text/plain",
            MUTABLE_CACHE_CONTROL,
        );
        assert_static_metadata(
            &files,
            "channels/stable/00",
            "application/octet-stream",
            MUTABLE_CACHE_CONTROL,
        );
        assert_static_metadata(
            &files,
            "objects/aa/object",
            "application/octet-stream",
            IMMUTABLE_CACHE_CONTROL,
        );
        assert_static_metadata(
            &files,
            TEST_LOOSE_OBJECT_PATH,
            "application/octet-stream",
            MUTABLE_CACHE_CONTROL,
        );
        let disk_path = files
            .iter()
            .find(|file| file.class == StaticOriginClass::ImageDisk)
            .unwrap()
            .relative_path
            .clone();
        let disk = files
            .iter()
            .find(|file| file.relative_path == disk_path)
            .unwrap();
        assert_eq!(disk.content_type, "application/vnd.aos.disk-image.qcow2");
        assert_eq!(disk.cache_control, IMMUTABLE_CACHE_CONTROL);
        assert_eq!(disk.sha256.as_deref().map(str::len), Some(64));
        assert_eq!(
            disk.content_disposition.as_deref(),
            Some("attachment; filename=\"aos-test.qcow2\"")
        );
        assert_static_metadata(
            &files,
            "releases/1/0/0/objects/pack/pack-demo.pack",
            "application/x-git-packed-objects",
            IMMUTABLE_CACHE_CONTROL,
        );
        assert_static_metadata(
            &files,
            "releases/1/0/0/objects/info/packs",
            "text/plain",
            MUTABLE_CACHE_CONTROL,
        );
        assert_static_metadata(
            &files,
            &files
                .iter()
                .find(|file| file.class == StaticOriginClass::Receipt)
                .unwrap()
                .relative_path,
            "application/vnd.aos.image-publication-receipt+json",
            IMMUTABLE_CACHE_CONTROL,
        );
        let receipt = files
            .iter()
            .find(|file| file.class == StaticOriginClass::Receipt)
            .unwrap();
        assert_eq!(receipt.sha256.as_deref().map(str::len), Some(64));
    }

    #[test]
    fn staged_image_disks_require_a_publication_receipt() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        std::fs::remove_dir_all(root.join("aos-static-origin/publication-receipts")).unwrap();

        let error = collect_static_origin_files(&root).unwrap_err();
        assert!(
            format!("{error:#}").contains("no durable receipt for current commit"),
            "{error:#}"
        );
    }

    #[test]
    fn receipt_history_requires_a_receipt_for_current_commit() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        advance_fixture_commit(&root, b"advanced without a receipt");
        let repository = git2::Repository::open_bare(&root).unwrap();
        let commit = repository.head().unwrap().peel_to_commit().unwrap().id();
        std::fs::remove_file(root.join(format!(
            "aos-static-origin/publication-receipts/{commit}.json"
        )))
        .unwrap();
        std::fs::remove_dir_all(root.join("aos-image-staging")).unwrap();

        let error = collect_static_origin_files(&root).unwrap_err();
        assert!(
            format!("{error:#}").contains("no durable receipt for current commit"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn static_origin_upload_writes_filesystem_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        let dest = tmp.path().join("dest");
        let upload_urls = vec![format!("file://{}", dest.display())];
        let printer = Printer::new(0, true, false);

        let report = upload_static_origin_to_all(
            &root,
            &upload_urls,
            &AuthOptions::default(),
            false,
            &printer,
        )
        .await
        .unwrap();

        assert!(report.files >= 6);
        assert_eq!(
            std::fs::read(dest.join("HEAD")).unwrap(),
            b"ref: refs/heads/stable\n"
        );
        assert_eq!(std::fs::read(dest.join("info/refs")).unwrap(), b"refs\n");
        assert_eq!(
            std::fs::read(dest.join("objects/aa/object")).unwrap(),
            b"object"
        );
        assert_eq!(
            std::fs::read(dest.join(TEST_LOOSE_OBJECT_PATH)).unwrap(),
            b"canonical-object"
        );
        assert_eq!(
            std::fs::read(dest.join("channels/stable/00")).unwrap(),
            b"channel"
        );
    }

    #[tokio::test]
    async fn static_origin_upload_replaces_equivalent_loose_wire_encoding() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        let dest = tmp.path().join("dest");
        std::fs::create_dir_all(dest.join("objects/ab")).unwrap();
        std::fs::write(dest.join(TEST_LOOSE_OBJECT_PATH), b"legacy-zlib-object").unwrap();

        upload_static_origin_to_all(
            &root,
            &[format!("file://{}", dest.display())],
            &AuthOptions::default(),
            false,
            &Printer::new(0, true, false),
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::read(dest.join(TEST_LOOSE_OBJECT_PATH)).unwrap(),
            b"canonical-object"
        );
    }

    #[tokio::test]
    async fn later_commit_uses_exact_remote_images_without_local_staging() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        let dest = tmp.path().join("dest");
        let upload_urls = vec![format!("file://{}", dest.display())];
        let printer = Printer::new(0, true, false);
        upload_static_origin_to_all(
            &root,
            &upload_urls,
            &AuthOptions::default(),
            false,
            &printer,
        )
        .await
        .unwrap();

        std::fs::remove_dir_all(root.join("aos-image-staging")).unwrap();
        advance_fixture_commit(&root, b"metadata-two");
        upload_static_origin_to_all(
            &root,
            &upload_urls,
            &AuthOptions::default(),
            false,
            &printer,
        )
        .await
        .unwrap();
        assert_eq!(
            std::fs::read(dest.join("channels/stable/00")).unwrap(),
            b"metadata-two"
        );

        let disk = collect_static_origin_files(&root)
            .unwrap()
            .into_iter()
            .find(|file| file.class == StaticOriginClass::ImageDisk)
            .unwrap();
        std::fs::write(dest.join(&disk.relative_path), b"wrong remote").unwrap();
        advance_fixture_commit(&root, b"metadata-three");
        let error = upload_static_origin_to_all(
            &root,
            &upload_urls,
            &AuthOptions::default(),
            false,
            &printer,
        )
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("staged image object"),
            "{error:#}"
        );
        assert_eq!(
            std::fs::read(dest.join("channels/stable/00")).unwrap(),
            b"metadata-two",
            "mismatched remote identity must keep mutable pointers stale"
        );
    }

    #[tokio::test]
    async fn static_origin_upload_to_all_reports_partial_failures() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let printer = Printer::new(0, true, false);

        let upload_urls = vec![
            format!("file://{}", first.path().display()),
            "not-a-url".to_string(),
            format!("file://{}", second.path().display()),
        ];
        let err = upload_static_origin_to_all(
            &root,
            &upload_urls,
            &AuthOptions::default(),
            false,
            &printer,
        )
        .await
        .unwrap_err();

        let message = format!("{err:#}");
        assert!(message.contains("static origin upload failed for 1/3 destination"));
        assert!(message.contains("not-a-url"));
        for dest in [first.path(), second.path()] {
            assert!(!dest.join("HEAD").exists());
            assert_eq!(
                std::fs::read(dest.join("objects/aa/object")).unwrap(),
                b"object"
            );
        }
    }

    #[tokio::test]
    async fn static_origin_upload_is_phase_major_across_destinations() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        let printer = Printer::new(0, true, false);

        let files = collect_static_origin_files(&root).unwrap();
        let log = UploadLog::default();
        let destinations: Vec<(&str, Box<dyn CacheBackend>)> = vec![
            ("dest-a", Box::new(RecordingBackend::new("dest-a", &log))),
            ("dest-b", Box::new(RecordingBackend::new("dest-b", &log))),
        ];

        let (failures, _skipped) =
            upload_phase_major(&files, &destinations, false, true, &printer).await;
        assert!(failures.is_empty(), "{failures:?}");

        let class_of = |path: &str| {
            files
                .iter()
                .find(|file| file.relative_path == path)
                .unwrap_or_else(|| panic!("unknown uploaded path {path}"))
                .class
        };
        let events = log.lock().unwrap();
        let immutable_count = files
            .iter()
            .filter(|file| file.class != StaticOriginClass::Mutable)
            .count();
        assert_eq!(events.len(), files.len() * 2);

        // Every immutable upload — on both destinations — precedes the
        // first mutable upload anywhere.
        let first_mutable = events
            .iter()
            .position(|(_, path)| class_of(path) == StaticOriginClass::Mutable)
            .unwrap();
        assert_eq!(first_mutable, immutable_count * 2);
        let image_disk_count = files
            .iter()
            .filter(|file| file.class == StaticOriginClass::ImageDisk)
            .count();
        let first_catalog = events
            .iter()
            .position(|(_, path)| class_of(path) == StaticOriginClass::Immutable)
            .unwrap();
        assert_eq!(first_catalog, image_disk_count * 2);
        let catalog_count = files
            .iter()
            .filter(|file| file.class == StaticOriginClass::Immutable)
            .count();
        let first_receipt = events
            .iter()
            .position(|(_, path)| class_of(path) == StaticOriginClass::Receipt)
            .unwrap();
        assert_eq!(first_receipt, (image_disk_count + catalog_count) * 2);
        for dest in ["dest-a", "dest-b"] {
            assert_eq!(
                events[..first_mutable]
                    .iter()
                    .filter(|(name, _)| name == dest)
                    .count(),
                immutable_count,
                "{dest} immutable uploads must all precede the mutable phase"
            );
        }
    }

    #[tokio::test]
    async fn destination_failing_immutable_phase_receives_no_mutable_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        let printer = Printer::new(0, true, false);

        let files = collect_static_origin_files(&root).unwrap();
        let log = UploadLog::default();
        let destinations: Vec<(&str, Box<dyn CacheBackend>)> = vec![
            ("healthy", Box::new(RecordingBackend::new("healthy", &log))),
            (
                "broken",
                Box::new(RecordingBackend::new("broken", &log).failing_on("objects/aa/object")),
            ),
        ];

        let (failures, _skipped) =
            upload_phase_major(&files, &destinations, false, true, &printer).await;
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("broken"), "{failures:?}");
        assert!(failures[0].contains("objects/aa/object"), "{failures:?}");

        let events = log.lock().unwrap();
        let class_of = |path: &str| {
            files
                .iter()
                .find(|file| file.relative_path == path)
                .unwrap()
                .class
        };
        // A failure at any required destination keeps mutable pointers stale
        // everywhere, so no placement can discover a partially replicated
        // image release.
        assert!(
            events
                .iter()
                .all(|(_, path)| class_of(path) != StaticOriginClass::Mutable),
            "no destination may receive mutable files: {events:?}"
        );
        let immutable_count = files
            .iter()
            .filter(|file| file.class != StaticOriginClass::Mutable)
            .count();
        assert_eq!(
            events.iter().filter(|(name, _)| name == "healthy").count(),
            immutable_count
        );
    }

    #[tokio::test]
    async fn destination_failing_receipt_phase_keeps_all_refs_stale() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        let printer = Printer::new(0, true, false);
        let files = collect_static_origin_files(&root).unwrap();
        let receipt = files
            .iter()
            .find(|file| file.class == StaticOriginClass::Receipt)
            .unwrap()
            .relative_path
            .clone();
        let log = UploadLog::default();
        let destinations: Vec<(&str, Box<dyn CacheBackend>)> = vec![
            ("healthy", Box::new(RecordingBackend::new("healthy", &log))),
            (
                "broken",
                Box::new(RecordingBackend::new("broken", &log).failing_on(&receipt)),
            ),
        ];

        let (failures, _skipped) =
            upload_phase_major(&files, &destinations, false, true, &printer).await;
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains(&receipt), "{failures:?}");
        let events = log.lock().unwrap();
        let class_of = |path: &str| {
            files
                .iter()
                .find(|file| file.relative_path == path)
                .unwrap()
                .class
        };
        assert!(
            events
                .iter()
                .all(|(_, path)| class_of(path) != StaticOriginClass::Mutable),
            "receipt failure must keep every destination's refs stale: {events:?}"
        );
    }

    #[test]
    fn content_type_maps_web_surface_extensions() {
        assert_eq!(content_type("ui/app.wasm"), "application/wasm");
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("ui/app.js"), "text/javascript");
        assert_eq!(content_type("ui/style.css"), "text/css");
        assert_eq!(content_type("ui/manifest.json"), "application/json");
        assert_eq!(
            content_type(
                "images/sha256/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/aos.img.zst"
            ),
            "application/vnd.aos.disk-image.raw+zstd"
        );
    }

    /// Shared upload event log: `(destination name, relative path)` in
    /// global upload order across all destinations.
    type UploadLog = std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>;

    /// Fake [`CacheBackend`] that records `put_static_file` calls into a
    /// shared log and optionally fails on one configured path.
    struct RecordingBackend {
        name: &'static str,
        log: UploadLog,
        fail_on: Option<String>,
    }

    impl RecordingBackend {
        fn new(name: &'static str, log: &UploadLog) -> Self {
            Self {
                name,
                log: log.clone(),
                fail_on: None,
            }
        }

        fn failing_on(mut self, relative_path: &str) -> Self {
            self.fail_on = Some(relative_path.to_string());
            self
        }
    }

    #[async_trait::async_trait]
    impl CacheBackend for RecordingBackend {
        async fn has_narinfo(&self, _store_hash: &str) -> Result<bool> {
            unimplemented!("not used by static origin upload")
        }

        async fn get_narinfo(&self, _store_hash: &str) -> Result<String> {
            unimplemented!("not used by static origin upload")
        }

        async fn put_narinfo(&self, _store_hash: &str, _content: &str) -> Result<()> {
            unimplemented!("not used by static origin upload")
        }

        async fn get_nar(&self, _url: &str) -> Result<Vec<u8>> {
            unimplemented!("not used by static origin upload")
        }

        async fn put_nar(&self, _filename: &str, _data: &[u8]) -> Result<()> {
            unimplemented!("not used by static origin upload")
        }

        async fn query_missing(&self, _store_hashes: &[&str]) -> Result<Vec<String>> {
            unimplemented!("not used by static origin upload")
        }

        async fn ensure_cache_info(&self, _store_dir: &str) -> Result<()> {
            unimplemented!("not used by static origin upload")
        }

        async fn put_cache_info(&self, _content: &str) -> Result<()> {
            unimplemented!("not used by static origin upload")
        }

        async fn exists(&self, _relative_path: &str) -> Result<bool> {
            // The recording backend treats every object as absent, so the
            // skip-cached fast path never fires and the upload log records
            // every file (the ordering invariant under test).
            Ok(false)
        }

        async fn put_static_file(
            &self,
            relative_path: &str,
            _source: &std::path::Path,
            _content_type: Option<&str>,
            _cache_control: Option<&str>,
            _content_disposition: Option<&str>,
            _sha256: Option<&str>,
        ) -> Result<()> {
            if self.fail_on.as_deref() == Some(relative_path) {
                bail!("injected failure uploading {relative_path}");
            }
            self.log
                .lock()
                .unwrap()
                .push((self.name.to_string(), relative_path.to_string()));
            Ok(())
        }
    }

    fn write_fixture_origin(root: &Path) {
        let repository = git2::Repository::init_bare(root).unwrap();
        let tree_oid = repository.treebuilder(None).unwrap().write().unwrap();
        let tree = repository.find_tree(tree_oid).unwrap();
        let signature = git2::Signature::now("AOS Test", "aos@example.invalid").unwrap();
        let commit = repository
            .commit(
                Some("refs/heads/stable"),
                &signature,
                &signature,
                "fixture",
                &tree,
                &[],
            )
            .unwrap();
        repository.set_head("refs/heads/stable").unwrap();
        std::fs::create_dir_all(root.join("info")).unwrap();
        std::fs::create_dir_all(root.join("objects/aa")).unwrap();
        std::fs::create_dir_all(root.join("objects/ab")).unwrap();
        std::fs::create_dir_all(root.join("objects/info")).unwrap();
        std::fs::create_dir_all(root.join("channels/stable")).unwrap();
        std::fs::create_dir_all(root.join("releases/1/0/0/objects/pack")).unwrap();
        std::fs::create_dir_all(root.join("releases/1/0/0/objects/info")).unwrap();
        std::fs::create_dir_all(root.join("aos-static-origin/publication-receipts")).unwrap();
        let disk_bytes = b"qcow2 bytes";
        let info_bytes = b"{}";
        let image_sha = hex::encode(Sha256::digest(disk_bytes));
        let info_sha = hex::encode(Sha256::digest(info_bytes));
        std::fs::create_dir_all(root.join(format!(
            "aos-image-staging/images/sha256/{image_sha}/metadata/{info_sha}"
        )))
        .unwrap();
        std::fs::write(root.join("info/refs"), b"refs\n").unwrap();
        std::fs::write(root.join("objects/aa/object"), b"object").unwrap();
        std::fs::write(root.join(TEST_LOOSE_OBJECT_PATH), b"canonical-object").unwrap();
        std::fs::write(
            root.join("objects/info/alternates"),
            b"../releases/1/0/0/objects/\n",
        )
        .unwrap();
        std::fs::write(root.join("channels/stable/00"), b"channel").unwrap();
        std::fs::write(
            root.join("releases/1/0/0/objects/pack/pack-demo.pack"),
            b"pack",
        )
        .unwrap();
        std::fs::write(
            root.join("releases/1/0/0/objects/info/packs"),
            b"P pack-demo.pack\n",
        )
        .unwrap();
        std::fs::write(
            root.join(format!(
                "aos-image-staging/images/sha256/{image_sha}/aos-test.qcow2"
            )),
            disk_bytes,
        )
        .unwrap();
        std::fs::write(
            root.join(format!(
                "aos-image-staging/images/sha256/{image_sha}/metadata/{info_sha}/image-info.json"
            )),
            info_bytes,
        )
        .unwrap();
        let disk_key = format!("images/sha256/{image_sha}/aos-test.qcow2");
        let info_key = format!("images/sha256/{image_sha}/metadata/{info_sha}/image-info.json");
        let objects = serde_json::json!([
            {
                "key": disk_key.as_str(),
                "role": "disk",
                "byteSize": disk_bytes.len(),
                "sha256": image_sha.as_str(),
            },
            {
                "key": info_key.as_str(),
                "role": "image-info",
                "byteSize": info_bytes.len(),
                "sha256": info_sha.as_str(),
            }
        ]);
        let digest = aos_registry_surface::manifest::image_catalog_digest(
            "fixture",
            [
                (
                    disk_key.as_str(),
                    "disk",
                    disk_bytes.len() as u64,
                    image_sha.as_str(),
                ),
                (
                    info_key.as_str(),
                    "image-info",
                    info_bytes.len() as u64,
                    info_sha.as_str(),
                ),
            ],
        );
        std::fs::write(
            root.join(format!(
                "aos-static-origin/publication-receipts/{}.json",
                commit
            )),
            serde_json::to_vec(&serde_json::json!({
                "schemaVersion": 1,
                "commit": commit.to_string(),
                "registry": "fixture",
                "catalogDigest": digest,
                "objects": objects,
            }))
            .unwrap(),
        )
        .unwrap();
    }

    fn advance_fixture_commit(root: &Path, channel: &[u8]) {
        let repository = git2::Repository::open_bare(root).unwrap();
        let parent = repository.head().unwrap().peel_to_commit().unwrap();
        let tree = parent.tree().unwrap();
        let signature = git2::Signature::now("AOS Test", "aos@example.invalid").unwrap();
        let commit = repository
            .commit(
                Some("refs/heads/stable"),
                &signature,
                &signature,
                "metadata-only fixture",
                &tree,
                &[&parent],
            )
            .unwrap();
        let receipts = root.join("aos-static-origin/publication-receipts");
        let prior_path = receipts.join(format!("{}.json", parent.id()));
        let mut receipt: serde_json::Value =
            serde_json::from_slice(&std::fs::read(prior_path).unwrap()).unwrap();
        receipt["commit"] = serde_json::json!(commit.to_string());
        std::fs::write(
            receipts.join(format!("{commit}.json")),
            serde_json::to_vec(&receipt).unwrap(),
        )
        .unwrap();
        std::fs::write(root.join("channels/stable/00"), channel).unwrap();
    }

    fn assert_static_metadata(
        files: &[StaticOriginFile],
        relative_path: &str,
        content_type: &str,
        cache_control: &str,
    ) {
        let file = files
            .iter()
            .find(|file| file.relative_path == relative_path)
            .unwrap_or_else(|| panic!("missing static origin file {relative_path}"));
        assert_eq!(file.content_type, content_type, "{relative_path}");
        assert_eq!(file.cache_control, cache_control, "{relative_path}");
    }
}
