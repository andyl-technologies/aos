//! Static git-origin upload helpers.
//!
//! This uploads the dumb-HTTP git origin surface in producer-safe order:
//! immutable object/cache payloads first, mutable pointers last.

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use aos_cache::backend::{self, AuthOptions};
use aos_core::output::Printer;

use crate::registry::objectstore;

const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
const MUTABLE_CACHE_CONTROL: &str = "public, max-age=60, must-revalidate";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum StaticOriginClass {
    Immutable,
    Mutable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticOriginFile {
    pub relative_path: String,
    pub source: PathBuf,
    pub class: StaticOriginClass,
    pub content_type: &'static str,
    pub cache_control: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticOriginUploadReport {
    pub files: usize,
    pub bytes: u64,
}

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

    for upload_url in upload_urls {
        if let Err(err) = upload_static_origin(&files, upload_url, auth, printer).await {
            failures.push(format!("{upload_url}: {err:#}"));
        }
    }

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

async fn upload_static_origin(
    files: &[StaticOriginFile],
    upload_url: &str,
    auth: &AuthOptions,
    printer: &Printer,
) -> Result<()> {
    let backend = backend::from_url(upload_url, auth).await?;
    for file in files {
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
    printer.success(&format!(
        "Uploaded static registry origin files to {upload_url}"
    ));
    Ok(())
}

fn total_bytes(files: &[StaticOriginFile]) -> Result<u64> {
    let mut bytes = 0u64;
    for file in files {
        bytes += std::fs::metadata(&file.source)
            .with_context(|| format!("stat {}", file.source.display()))?
            .len();
    }
    Ok(bytes)
}

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

fn classify_git_path(relative_path: &str) -> Result<StaticOriginClass> {
    if relative_path.starts_with("objects/info/") {
        Ok(StaticOriginClass::Mutable)
    } else {
        Ok(StaticOriginClass::Immutable)
    }
}

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

fn cache_control(class: StaticOriginClass) -> &'static str {
    match class {
        StaticOriginClass::Immutable => IMMUTABLE_CACHE_CONTROL,
        StaticOriginClass::Mutable => MUTABLE_CACHE_CONTROL,
    }
}

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
}
