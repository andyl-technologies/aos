//! Static git-origin upload helpers.
//!
//! This uploads the dumb-HTTP git origin surface in producer-safe,
//! *phase-major* order across all destinations: every
//! [`StaticOriginClass::Immutable`] object/cache payload is uploaded to
//! *every* destination first, and only then are
//! [`StaticOriginClass::Mutable`] pointers (`HEAD`, `info/refs`, channel
//! partitions) uploaded — and only to the destinations whose immutable
//! phase fully succeeded. A destination that failed the immutable phase
//! is skipped in the mutable phase and left stale but consistent.
//!
//! The resulting invariant: any pointer visible on any mirror only
//! references objects present on every mirror that completed the
//! immutable phase. A consumer racing a partially completed upload can
//! therefore at worst see *old* pointers — never a pointer to content
//! that has not been uploaded yet, on any mirror.
//!
//! Every file is classified as [`StaticOriginClass::Immutable`]
//! (content-addressed git objects, release packs, narinfos, NARs) or
//! [`StaticOriginClass::Mutable`] (refs, channel partitions, server-info
//! metadata) and tagged with matching `Cache-Control` and `Content-Type`
//! headers for CDN-fronted hosting.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_cache::backend::{self, AuthOptions, CacheBackend};
use aos_core::output::Printer;

use crate::registry::objectstore;

/// `Cache-Control` for content-addressed files that never change in place.
const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
/// `Cache-Control` for pointer files that are rewritten on every publish.
const MUTABLE_CACHE_CONTROL: &str = "public, max-age=60, must-revalidate";

/// Mutability class of a static origin file.
///
/// The `Ord` impl orders `Immutable` before `Mutable`, which is the safe
/// upload order: payloads land before the pointers that reference them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StaticOriginClass {
    /// Content-addressed payload (git objects, packs, narinfos, NARs).
    Immutable,
    /// Pointer or metadata rewritten on publish (`HEAD`, `info/refs`,
    /// `objects/info/*`, channel partitions, `nix-cache-info`).
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
}

/// Collect the full static origin file set in safe upload order.
///
/// Walks the registry's git directory (`HEAD`, `info/refs`, `objects/`,
/// `releases/`, `channels/`) and, when `cache_dir` is given, the static Nix
/// cache (`nix-cache-info`, `*.narinfo`, `nar/`). Files are classified and
/// sorted immutable-first, then by path. Missing optional directories are
/// skipped.
///
/// # Errors
///
/// Returns an error if the git directory cannot be resolved, a directory
/// cannot be read, or a file path contains non-UTF-8 or unsafe components.
pub fn collect_static_origin_files(
    registry_dir: &Path,
    cache_dir: Option<&Path>,
) -> Result<Vec<StaticOriginFile>> {
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

    if let Some(cache_dir) = cache_dir {
        push_file(
            &mut files,
            cache_dir,
            "nix-cache-info",
            StaticOriginClass::Mutable,
        )?;
        push_cache_narinfos(&mut files, cache_dir)?;
        push_dir(&mut files, cache_dir, "nar", |_| {
            Ok(StaticOriginClass::Immutable)
        })?;
    }

    files.sort_by(|a, b| {
        a.class
            .cmp(&b.class)
            .then_with(|| a.relative_path.cmp(&b.relative_path))
    });
    Ok(files)
}

/// Upload the static origin surface to every destination URL in
/// phase-major order.
///
/// The immutable phase runs first: every [`StaticOriginClass::Immutable`]
/// file is uploaded to *every* destination before any mutable pointer is
/// uploaded anywhere. The mutable phase then uploads
/// [`StaticOriginClass::Mutable`] files only to the destinations whose
/// immutable phase fully succeeded; a destination that failed the
/// immutable phase is skipped with a warning and left stale but
/// consistent. This preserves the cross-mirror invariant: any pointer
/// visible on any mirror only references objects present on every mirror
/// that completed the immutable phase.
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
    cache_dir: Option<&Path>,
    upload_urls: &[String],
    auth: &AuthOptions,
    printer: &Printer,
) -> Result<StaticOriginUploadReport> {
    if upload_urls.is_empty() {
        bail!("at least one upload URL is required");
    }

    let files = collect_static_origin_files(registry_dir, cache_dir)?;
    if files.is_empty() {
        bail!("static origin has no files to upload");
    }

    let bytes = total_bytes(&files)?;
    let report = StaticOriginUploadReport {
        files: files.len(),
        bytes,
    };
    let mut failures = Vec::new();
    let mut destinations: Vec<(&str, Box<dyn CacheBackend>)> = Vec::new();

    for upload_url in upload_urls {
        match backend::from_url(upload_url, auth).await {
            Ok(backend) => destinations.push((upload_url.as_str(), backend)),
            Err(err) => failures.push(format!("{upload_url}: {err:#}")),
        }
    }

    failures.extend(upload_phase_major(&files, &destinations, printer).await);

    if !failures.is_empty() {
        bail!(
            "static origin upload failed for {}/{} destination(s):\n{}",
            failures.len(),
            upload_urls.len(),
            failures.join("\n")
        );
    }

    Ok(report)
}

/// Upload `files` to already-connected destinations in phase-major order.
///
/// Phase 1 uploads every [`StaticOriginClass::Immutable`] file to every
/// destination. Phase 2 uploads [`StaticOriginClass::Mutable`] files only
/// to the destinations whose immutable phase fully succeeded; a
/// destination that failed phase 1 is skipped with a warning, leaving it
/// stale but consistent. Within each phase, the collected file order is
/// preserved.
///
/// Returns at most one failure message per failed destination; an empty
/// vector means every destination completed both phases.
async fn upload_phase_major(
    files: &[StaticOriginFile],
    destinations: &[(&str, Box<dyn CacheBackend>)],
    printer: &Printer,
) -> Vec<String> {
    let mut failures = Vec::new();
    let mut immutable_ok = Vec::with_capacity(destinations.len());

    for (upload_url, backend) in destinations {
        match upload_class(backend.as_ref(), files, StaticOriginClass::Immutable).await {
            Ok(()) => immutable_ok.push(true),
            Err(err) => {
                failures.push(format!("{upload_url}: {err:#}"));
                immutable_ok.push(false);
            }
        }
    }

    for ((upload_url, backend), ok) in destinations.iter().zip(immutable_ok) {
        if !ok {
            printer.warning(&format!(
                "Skipping mutable pointer upload to {upload_url}: immutable phase failed \
                 (destination left stale but consistent)"
            ));
            continue;
        }
        match upload_class(backend.as_ref(), files, StaticOriginClass::Mutable).await {
            Ok(()) => printer.success(&format!(
                "Uploaded static registry origin files to {upload_url}"
            )),
            Err(err) => failures.push(format!("{upload_url}: {err:#}")),
        }
    }

    failures
}

/// Upload every file of one mutability class to a single backend,
/// preserving the collected order; stops at the first failure.
async fn upload_class(
    backend: &dyn CacheBackend,
    files: &[StaticOriginFile],
    class: StaticOriginClass,
) -> Result<()> {
    for file in files.iter().filter(|file| file.class == class) {
        backend
            .put_static_file(
                &file.relative_path,
                &file.source,
                Some(file.content_type),
                Some(file.cache_control),
            )
            .await
            .with_context(|| format!("uploading {}", file.relative_path))?;
    }
    Ok(())
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

/// Add every `*.narinfo` file at the top level of the static cache dir.
fn push_cache_narinfos(files: &mut Vec<StaticOriginFile>, cache_dir: &Path) -> Result<()> {
    if !cache_dir.is_dir() {
        return Ok(());
    }
    for entry in
        std::fs::read_dir(cache_dir).with_context(|| format!("reading {}", cache_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) == Some("narinfo") && path.is_file() {
            push_source(files, cache_dir, path, StaticOriginClass::Immutable)?;
        }
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

/// Pick a `Content-Type` for a static origin path by name and extension.
fn content_type(relative_path: &str) -> &'static str {
    if relative_path == "nix-cache-info"
        || relative_path == "HEAD"
        || relative_path == "info/refs"
        || relative_path.starts_with("objects/info/")
    {
        "text/plain"
    } else if relative_path.ends_with(".narinfo") {
        "text/x-nix-narinfo"
    } else if relative_path.ends_with(".pack") {
        "application/x-git-packed-objects"
    } else if relative_path.ends_with(".idx") {
        "application/x-git-packed-objects-toc"
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
    } else if relative_path.ends_with(".json") {
        "application/json"
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
        let cache = tmp.path().join("cache");
        write_fixture_cache(&cache);

        let files = collect_static_origin_files(&root, Some(&cache)).unwrap();
        let paths = files
            .iter()
            .map(|file| (file.relative_path.as_str(), file.class))
            .collect::<Vec<_>>();

        assert!(paths.contains(&("objects/aa/object", StaticOriginClass::Immutable)));
        assert!(paths.contains(&(
            "releases/1/0/0/objects/pack/pack-demo.pack",
            StaticOriginClass::Immutable
        )));
        assert!(paths.contains(&("abc123.narinfo", StaticOriginClass::Immutable)));
        assert!(paths.contains(&("nar/demo.nar.zst", StaticOriginClass::Immutable)));
        assert!(paths.contains(&("HEAD", StaticOriginClass::Mutable)));
        assert!(paths.contains(&("info/refs", StaticOriginClass::Mutable)));
        assert!(paths.contains(&("objects/info/alternates", StaticOriginClass::Mutable)));
        assert!(paths.contains(&("channels/stable/00", StaticOriginClass::Mutable)));

        let first_mutable = files
            .iter()
            .position(|file| file.class == StaticOriginClass::Mutable)
            .unwrap();
        assert!(
            files[..first_mutable]
                .iter()
                .all(|file| file.class == StaticOriginClass::Immutable)
        );
        assert!(
            files[first_mutable..]
                .iter()
                .all(|file| file.class == StaticOriginClass::Mutable)
        );
    }

    #[test]
    fn static_origin_files_carry_cdn_cache_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        let cache = tmp.path().join("cache");
        write_fixture_cache(&cache);

        let files = collect_static_origin_files(&root, Some(&cache)).unwrap();
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
        assert_static_metadata(
            &files,
            "abc123.narinfo",
            "text/x-nix-narinfo",
            IMMUTABLE_CACHE_CONTROL,
        );
        assert_static_metadata(
            &files,
            "nar/demo.nar.zst",
            "application/zstd",
            IMMUTABLE_CACHE_CONTROL,
        );
    }

    #[tokio::test]
    async fn static_origin_upload_writes_filesystem_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        let cache = tmp.path().join("cache");
        write_fixture_cache(&cache);
        let dest = tmp.path().join("dest");
        let upload_urls = vec![format!("file://{}", dest.display())];
        let printer = Printer::new(0, true, false);

        let report = upload_static_origin_to_all(
            &root,
            Some(&cache),
            &upload_urls,
            &AuthOptions::default(),
            &printer,
        )
        .await
        .unwrap();

        assert!(report.files >= 8);
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
        assert_eq!(
            std::fs::read(dest.join("nar/demo.nar.zst")).unwrap(),
            b"nar"
        );
    }

    #[tokio::test]
    async fn static_origin_upload_to_all_reports_partial_failures() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        let cache = tmp.path().join("cache");
        write_fixture_cache(&cache);
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
            Some(&cache),
            &upload_urls,
            &AuthOptions::default(),
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
                std::fs::read(dest.join("abc123.narinfo")).unwrap(),
                b"narinfo"
            );
            assert_eq!(
                std::fs::read(dest.join("nar/demo.nar.zst")).unwrap(),
                b"nar"
            );
        }
    }

    #[tokio::test]
    async fn static_origin_upload_is_phase_major_across_destinations() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().join("origin.git");
        write_fixture_origin(&root);
        let cache = tmp.path().join("cache");
        write_fixture_cache(&cache);
        let printer = Printer::new(0, true, false);

        let files = collect_static_origin_files(&root, Some(&cache)).unwrap();
        let log = UploadLog::default();
        let destinations: Vec<(&str, Box<dyn CacheBackend>)> = vec![
            ("dest-a", Box::new(RecordingBackend::new("dest-a", &log))),
            ("dest-b", Box::new(RecordingBackend::new("dest-b", &log))),
        ];

        let failures = upload_phase_major(&files, &destinations, &printer).await;
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
            .filter(|file| file.class == StaticOriginClass::Immutable)
            .count();
        assert_eq!(events.len(), files.len() * 2);

        // Every immutable upload — on both destinations — precedes the
        // first mutable upload anywhere.
        let first_mutable = events
            .iter()
            .position(|(_, path)| class_of(path) == StaticOriginClass::Mutable)
            .unwrap();
        assert_eq!(first_mutable, immutable_count * 2);
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
        let cache = tmp.path().join("cache");
        write_fixture_cache(&cache);
        let printer = Printer::new(0, true, false);

        let files = collect_static_origin_files(&root, Some(&cache)).unwrap();
        let log = UploadLog::default();
        let destinations: Vec<(&str, Box<dyn CacheBackend>)> = vec![
            ("healthy", Box::new(RecordingBackend::new("healthy", &log))),
            (
                "broken",
                Box::new(RecordingBackend::new("broken", &log).failing_on("objects/aa/object")),
            ),
        ];

        let failures = upload_phase_major(&files, &destinations, &printer).await;
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
        // The failing destination must receive no mutable pointers: it is
        // left stale but consistent.
        assert!(
            events
                .iter()
                .filter(|(name, _)| name == "broken")
                .all(|(_, path)| class_of(path) == StaticOriginClass::Immutable),
            "broken destination must not receive mutable files: {events:?}"
        );
        // The healthy destination completes both phases in full.
        assert_eq!(
            events.iter().filter(|(name, _)| name == "healthy").count(),
            files.len()
        );
    }

    #[test]
    fn content_type_maps_web_surface_extensions() {
        assert_eq!(content_type("ui/app.wasm"), "application/wasm");
        assert_eq!(content_type("index.html"), "text/html; charset=utf-8");
        assert_eq!(content_type("ui/app.js"), "text/javascript");
        assert_eq!(content_type("ui/style.css"), "text/css");
        assert_eq!(content_type("ui/manifest.json"), "application/json");
    }

    /// Shared upload event log: `(destination name, relative path)` in
    /// global upload order across all destinations.
    type UploadLog = std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>;

    /// Fake [`CacheBackend`] that records `put_static_file` calls into a
    /// shared log and optionally fails on one configured path.
    struct RecordingBackend {
        name: &'static str,
        log: UploadLog,
        fail_on: Option<&'static str>,
    }

    impl RecordingBackend {
        fn new(name: &'static str, log: &UploadLog) -> Self {
            Self {
                name,
                log: log.clone(),
                fail_on: None,
            }
        }

        fn failing_on(mut self, relative_path: &'static str) -> Self {
            self.fail_on = Some(relative_path);
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

        async fn put_static_file(
            &self,
            relative_path: &str,
            _source: &std::path::Path,
            _content_type: Option<&str>,
            _cache_control: Option<&str>,
        ) -> Result<()> {
            if self.fail_on == Some(relative_path) {
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

    fn write_fixture_cache(cache: &Path) {
        std::fs::create_dir_all(cache.join("nar")).unwrap();
        std::fs::write(cache.join("nix-cache-info"), b"StoreDir: /nix/store\n").unwrap();
        std::fs::write(cache.join("abc123.narinfo"), b"narinfo").unwrap();
        std::fs::write(cache.join("nar/demo.nar.zst"), b"nar").unwrap();
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
