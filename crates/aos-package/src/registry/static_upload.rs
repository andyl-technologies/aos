//! Static git-origin upload helpers.
//!
//! This uploads the dumb-HTTP git origin surface in producer-safe order:
//! immutable object payloads first, mutable pointers last. A consumer racing a
//! partially completed upload can therefore at worst see *old* pointers
//! (`HEAD`, `info/refs`, channel partitions) — never a pointer to content that
//! has not been uploaded yet.
//!
//! Every file is classified as [`StaticOriginClass::Immutable`]
//! (content-addressed git objects and release packs) or
//! [`StaticOriginClass::Mutable`] (refs, channel partitions, server-info
//! metadata) and tagged with matching `Cache-Control` and `Content-Type`
//! headers for CDN-fronted hosting. The static binary cache (narinfos, NARs,
//! `nix-cache-info`) is uploaded separately, and owns its own §8 write
//! ordering, in [`crate::registry::nixcache::upload_static_cache_to_all`].

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_cache::backend::{self, AuthOptions, IMMUTABLE_CACHE_CONTROL, MUTABLE_CACHE_CONTROL};
use aos_core::output::Printer;
use futures_util::future::join_all;
use futures_util::stream::{StreamExt, TryStreamExt};

use crate::registry::objectstore;

/// Maximum origin-file uploads kept in flight per destination. The
/// `aos_net` connection pool enforces the real per-host limit; this only
/// bounds how many requests we stage at once.
const UPLOAD_CONCURRENCY: usize = 16;

/// Mutability class of a static origin file.
///
/// The `Ord` impl orders `Immutable` before `Mutable`, which is the safe
/// upload order: payloads land before the pointers that reference them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StaticOriginClass {
    /// Content-addressed payload (git objects and release packs).
    Immutable,
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
/// `releases/`, `channels/`), classifies each file, and sorts immutable-first
/// then by path. Missing optional directories are skipped. The static binary
/// cache is uploaded separately (see the module docs).
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
    push_dir(&mut files, &git_dir, "releases", |_| {
        Ok(StaticOriginClass::Immutable)
    })?;
    push_dir(&mut files, &git_dir, "channels", |_| {
        Ok(StaticOriginClass::Mutable)
    })?;

    files.sort_by(|a, b| {
        a.class
            .cmp(&b.class)
            .then_with(|| a.relative_path.cmp(&b.relative_path))
    });
    Ok(files)
}

/// Upload the git-origin surface to every destination URL.
///
/// All destinations receive the same file set in immutable-before-mutable
/// order. Destinations are attempted independently: a failure on one does
/// not stop uploads to the others.
///
/// # Errors
///
/// Returns an error when no upload URL is given, the origin has no files,
/// a source file cannot be stat'ed, or any destination upload fails (the
/// error aggregates all per-destination failures).
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
    let results = join_all(upload_urls.iter().map(|upload_url| {
        let files = &files;
        async move {
            upload_static_origin(files, upload_url, auth, no_skip, printer)
                .await
                .map_err(|err| format!("{upload_url}: {err:#}"))
        }
    }))
    .await;

    let skipped_files = results
        .iter()
        .filter_map(|result| result.as_ref().ok())
        .map(|report| report.skipped_files)
        .sum();
    let failures: Vec<String> = results.into_iter().filter_map(Result::err).collect();
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

/// Upload the collected files to one destination.
///
/// Immutable payloads are uploaded first (concurrently), then — as a
/// barrier — the mutable pointers, preserving the producer-safe ordering
/// guarantee while parallelizing within each class.
async fn upload_static_origin(
    files: &[StaticOriginFile],
    upload_url: &str,
    auth: &AuthOptions,
    no_skip: bool,
    printer: &Printer,
) -> Result<StaticOriginUploadReport> {
    let backend = backend::from_url(upload_url, auth).await?;
    let backend = &*backend;
    let mut skipped_files = 0usize;

    for class in [StaticOriginClass::Immutable, StaticOriginClass::Mutable] {
        let results =
            futures_util::stream::iter(files.iter().filter(|file| file.class == class).map(
                |file| async move {
                    if !no_skip
                        && file.class == StaticOriginClass::Immutable
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
                        )
                        .await
                        .with_context(|| format!("uploading {}", file.relative_path))?;
                    Ok::<bool, anyhow::Error>(false)
                },
            ))
            .buffer_unordered(UPLOAD_CONCURRENCY)
            .try_collect::<Vec<bool>>()
            .await?;
        skipped_files += results.into_iter().filter(|skipped| *skipped).count();
    }

    printer.success(&format!(
        "Uploaded static registry origin files to {upload_url}"
    ));
    Ok(StaticOriginUploadReport {
        files: files.len(),
        bytes: total_bytes(files)?,
        skipped_files,
    })
}

/// Sum the on-disk size of every collected file.
fn total_bytes(files: &[StaticOriginFile]) -> Result<u64> {
    let mut bytes = 0u64;
    for file in files {
        bytes += std::fs::metadata(&file.source)
            .with_context(|| format!("stat {}", file.source.display()))?
            .len();
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
        relative_path,
        source,
        class,
    });
    Ok(())
}

/// Classify a path under `objects/`: `objects/info/*` metadata is mutable,
/// content-addressed objects and packs are immutable.
fn classify_git_path(relative_path: &str) -> Result<StaticOriginClass> {
    if relative_path.starts_with("objects/info/") {
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
        StaticOriginClass::Immutable => IMMUTABLE_CACHE_CONTROL,
        StaticOriginClass::Mutable => MUTABLE_CACHE_CONTROL,
    }
}

/// Pick a `Content-Type` for a git-origin path by name and extension.
fn content_type(relative_path: &str) -> &'static str {
    if relative_path == "HEAD"
        || relative_path == "info/refs"
        || relative_path.starts_with("objects/info/")
    {
        "text/plain"
    } else if relative_path.ends_with(".pack") {
        "application/x-git-packed-objects"
    } else if relative_path.ends_with(".idx") {
        "application/x-git-packed-objects-toc"
    } else if relative_path.ends_with(".zst") {
        "application/zstd"
    } else {
        "application/octet-stream"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(paths.contains(&(
            "releases/1/0/0/objects/pack/pack-demo.pack",
            StaticOriginClass::Immutable
        )));
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
            "releases/1/0/0/objects/pack/pack-demo.pack",
            "application/x-git-packed-objects",
            IMMUTABLE_CACHE_CONTROL,
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
            std::fs::read(dest.join("channels/stable/00")).unwrap(),
            b"channel"
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
            assert_eq!(
                std::fs::read(dest.join("HEAD")).unwrap(),
                b"ref: refs/heads/stable\n"
            );
            assert_eq!(
                std::fs::read(dest.join("objects/aa/object")).unwrap(),
                b"object"
            );
        }
    }

    fn write_fixture_origin(root: &Path) {
        std::fs::create_dir_all(root.join("info")).unwrap();
        std::fs::create_dir_all(root.join("objects/aa")).unwrap();
        std::fs::create_dir_all(root.join("objects/info")).unwrap();
        std::fs::create_dir_all(root.join("channels/stable")).unwrap();
        std::fs::create_dir_all(root.join("releases/1/0/0/objects/pack")).unwrap();
        std::fs::write(root.join("HEAD"), b"ref: refs/heads/stable\n").unwrap();
        std::fs::write(root.join("info/refs"), b"refs\n").unwrap();
        std::fs::write(root.join("objects/aa/object"), b"object").unwrap();
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
