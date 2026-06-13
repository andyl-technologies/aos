//! Static Nix binary-cache generation for registry store paths.
//!
//! Producer-side tooling that turns the store paths referenced by a
//! registry's package TOML files into a standard static Nix binary cache: a
//! `nix-cache-info` file, one `<hash>.narinfo` per path, and
//! zstd-compressed NARs under `nar/`. The local Nix store supplies the
//! bytes (`nix-store --dump`) and metadata (`nix path-info`); narinfos are
//! optionally Ed25519-signed.
//!
//! The cache is laid out on disk first ([`generate_static_cache`]) and then
//! mirrored to one or more upload destinations via `aos-cache` backends
//! ([`upload_static_cache`], [`upload_static_cache_to_all`]).
//! [`upsert_registry_cache`] records the published cache URL in the
//! registry's `registry.toml` so consumers discover it after sync.
//!
//! Store paths from the package metadata may live in an alternate store
//! directory (e.g. `/var/lib/store`); metadata reported by the local
//! `/nix/store` is re-rooted onto the requested store dir so the published
//! narinfos describe the paths consumers will actually install.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use aos_cache::backend::{self, AuthOptions};
use aos_core::nar::cache::{
    NarCompression, NarInfoSigner, StaticNarInfoInput, nar_url, nix_cache_info,
    render_static_narinfo,
};
use aos_core::nar::info::{basename, store_hash};
use aos_core::nix::aos_nix_env;
use aos_core::output::Printer;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use toml::Value as TomlValue;

/// Summary of a generated static cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticCacheReport {
    /// Number of store paths covered (registry roots plus their closures).
    pub paths: usize,
    /// Number of `.narinfo` files written.
    pub narinfos: usize,
    /// Number of compressed NAR files written.
    pub nars: usize,
    /// The directory the cache was generated into.
    pub output_dir: PathBuf,
}

/// Per-path metadata extracted from `nix path-info`, re-rooted onto the
/// registry's store directory.
#[derive(Debug, Clone)]
struct CachePathInfo {
    path: String,
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
    deriver: Option<String>,
}

/// Generate a complete static Nix binary cache for a registry's store paths.
///
/// Collects every `store_path`, `source_drv`, and sysroot image path from
/// the registry's package TOML files, expands each to its full closure with
/// `nix-store -qR`, and writes `nix-cache-info`, a zstd NAR, and a narinfo
/// for every member into `output_dir`. When `key_path` (or the signer's
/// default configuration) yields a signing key, narinfos are signed.
///
/// # Errors
///
/// Returns an error when the registry references no store paths, the paths
/// span mixed store directories, a path is missing from the local Nix
/// store, a `nix`/`nix-store` invocation fails, or an output file cannot be
/// written.
pub async fn generate_static_cache(
    registry_dir: &Path,
    output_dir: &Path,
    key_path: Option<&Path>,
    priority: u32,
    printer: &Printer,
) -> Result<StaticCacheReport> {
    let paths = collect_store_paths(registry_dir)?;
    if paths.is_empty() {
        bail!("registry contains no store paths to cache");
    }
    let store_dir = common_store_dir(&paths)?;

    // The ca/ trust map is the authority for blessed output bytes
    // (RFC-0005 §2.7). Generation reads the local store, so guard against
    // emitting a narinfo+NAR for a path whose local bytes were never
    // blessed — every enforcing consumer would reject it. Paths outside the
    // map (sources, images) are unaffected.
    let ca_map = super::ca::CaMap::load(registry_dir).context("loading ca/ trust map")?;

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating {}", output_dir.display()))?;
    std::fs::create_dir_all(output_dir.join("nar"))
        .with_context(|| format!("creating {}", output_dir.join("nar").display()))?;
    std::fs::write(
        output_dir.join("nix-cache-info"),
        nix_cache_info(&store_dir, priority),
    )
    .with_context(|| format!("writing {}", output_dir.join("nix-cache-info").display()))?;

    let signer = NarInfoSigner::load(key_path)?;
    let signer = signer.is_configured().then_some(signer);

    let mut narinfos = 0usize;
    let mut nars = 0usize;
    for path in &paths {
        printer.info(&format!("Generating static cache entry for {path}"));
        check_store_path_valid(path)?;
        let info = query_path_info(path)?;

        // If the trust map blesses this path, the local bytes must match a
        // blessed realisation before we publish them.
        if let Some(blessed) = ca_map.get(store_hash(&info.path)) {
            if !blessed
                .iter()
                .any(|entry| entry.matches_nar(&info.nar_hash, info.nar_size))
            {
                bail!(
                    "refusing to publish {}: local NAR ({} / {} bytes) is not blessed in ca/ \
                     — `apr ca bless` it or rebuild to a blessed realisation",
                    info.path,
                    info.nar_hash,
                    info.nar_size,
                );
            }
        }
        let compressed = dump_zstd_nar(&info.path)?;
        let file_hash = format!("sha256:{}", hex::encode(Sha256::digest(&compressed)));
        let file_size = compressed.len() as u64;

        let url = nar_url(&info.path, &info.nar_hash, NarCompression::Zstd);
        let nar_name = url
            .strip_prefix("nar/")
            .ok_or_else(|| anyhow::anyhow!("unexpected NAR URL '{url}'"))?;
        std::fs::write(output_dir.join("nar").join(nar_name), &compressed).with_context(|| {
            format!(
                "writing {}",
                output_dir.join("nar").join(nar_name).display()
            )
        })?;
        nars += 1;

        let body = render_static_narinfo(
            &StaticNarInfoInput {
                store_path: &info.path,
                nar_hash: &info.nar_hash,
                nar_size: info.nar_size,
                references: &info.references,
                deriver: info.deriver.as_deref(),
                signatures: &[],
                file_hash: &file_hash,
                file_size,
                compression: NarCompression::Zstd,
            },
            &store_dir,
            signer.as_ref(),
        );
        let hash = store_hash(&info.path);
        std::fs::write(output_dir.join(format!("{hash}.narinfo")), body)
            .with_context(|| format!("writing {}.narinfo", output_dir.join(hash).display()))?;
        narinfos += 1;
    }

    Ok(StaticCacheReport {
        paths: paths.len(),
        narinfos,
        nars,
        output_dir: output_dir.to_path_buf(),
    })
}

/// Upload a generated static cache directory to one destination.
///
/// Pushes `nix-cache-info`, every top-level `*.narinfo`, and every file
/// under `nar/` through the cache backend selected by `upload_url`'s scheme
/// (e.g. `file://`, S3-style object stores).
///
/// # Errors
///
/// Returns an error if the backend cannot be constructed for `upload_url`,
/// a local file cannot be read, or any upload request fails.
pub async fn upload_static_cache(
    output_dir: &Path,
    upload_url: &str,
    auth: &AuthOptions,
    printer: &Printer,
) -> Result<()> {
    let cache = backend::from_url(upload_url, auth).await?;
    let cache_info_path = output_dir.join("nix-cache-info");
    let cache_info = std::fs::read_to_string(&cache_info_path)
        .with_context(|| format!("reading {}", cache_info_path.display()))?;
    cache.put_cache_info(&cache_info).await?;

    for entry in std::fs::read_dir(output_dir)
        .with_context(|| format!("reading {}", output_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("narinfo") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        cache.put_narinfo(stem, &content).await?;
    }

    let nar_dir = output_dir.join("nar");
    if nar_dir.exists() {
        for entry in
            std::fs::read_dir(&nar_dir).with_context(|| format!("reading {}", nar_dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let data =
                std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
            cache.put_nar(name, &data).await?;
        }
    }

    printer.success(&format!("Uploaded static cache files to {upload_url}"));
    Ok(())
}

/// Upload a generated static cache to every destination URL.
///
/// Destinations are attempted independently; a failure on one does not stop
/// uploads to the others.
///
/// # Errors
///
/// Returns an error aggregating all per-destination failures when any
/// upload fails.
pub async fn upload_static_cache_to_all(
    output_dir: &Path,
    upload_urls: &[String],
    auth: &AuthOptions,
    printer: &Printer,
) -> Result<()> {
    let mut failures = Vec::new();

    for upload_url in upload_urls {
        if let Err(err) = upload_static_cache(output_dir, upload_url, auth, printer).await {
            failures.push(format!("{upload_url}: {err:#}"));
        }
    }

    if !failures.is_empty() {
        bail!(
            "static cache upload failed for {}/{} destination(s):\n{}",
            failures.len(),
            upload_urls.len(),
            failures.join("\n")
        );
    }

    Ok(())
}

/// Insert or update a `[[caches]]` entry in the registry's `registry.toml`.
///
/// Adds a `{ url, priority }` entry for `cache_url`, or updates the priority
/// of an existing entry with the same URL. Returns `true` when the file was
/// modified and `false` when it already matched.
///
/// # Errors
///
/// Returns an error when `registry.toml` cannot be read, parsed, or
/// rewritten, or when its `caches` value is not an array of tables.
pub fn upsert_registry_cache(registry_dir: &Path, cache_url: &str, priority: u32) -> Result<bool> {
    let path = registry_dir.join("registry.toml");
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut value: TomlValue =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;

    let root = value
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("registry.toml root is not a table"))?;
    let caches = root
        .entry("caches".to_string())
        .or_insert_with(|| TomlValue::Array(Vec::new()));
    let caches = caches
        .as_array_mut()
        .ok_or_else(|| anyhow::anyhow!("registry.toml [[caches]] is not an array"))?;

    let mut changed = false;
    if let Some(existing) = caches.iter_mut().find(|entry| {
        entry
            .get("url")
            .and_then(TomlValue::as_str)
            .map(|url| url == cache_url)
            .unwrap_or(false)
    }) {
        if existing.get("priority").and_then(TomlValue::as_integer) != Some(priority as i64) {
            existing
                .as_table_mut()
                .ok_or_else(|| anyhow::anyhow!("cache entry is not a table"))?
                .insert("priority".to_string(), TomlValue::Integer(priority as i64));
            changed = true;
        }
    } else {
        let mut table = toml::map::Map::new();
        table.insert("url".to_string(), TomlValue::String(cache_url.to_string()));
        table.insert("priority".to_string(), TomlValue::Integer(priority as i64));
        caches.push(TomlValue::Table(table));
        changed = true;
    }

    if changed {
        std::fs::write(&path, toml::to_string_pretty(&value)?)
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(changed)
}

/// Collect the sorted closure of every store path the registry references.
fn collect_store_paths(registry_dir: &Path) -> Result<Vec<String>> {
    let packages = registry_dir.join("packages");
    if !packages.exists() {
        return Ok(Vec::new());
    }
    let mut roots = BTreeSet::new();
    collect_store_paths_from_dir(&packages, &mut roots)?;

    let mut paths = BTreeSet::new();
    for root in roots {
        collect_store_path_closure(&root, &mut paths)?;
    }
    Ok(paths.into_iter().collect())
}

/// Determine the single store directory shared by all paths.
///
/// A static cache advertises one `StoreDir`, so mixed store roots cannot be
/// served from the same cache and are rejected.
fn common_store_dir(paths: &[String]) -> Result<String> {
    let first = paths
        .first()
        .ok_or_else(|| anyhow::anyhow!("registry contains no store paths to cache"))?;
    let store_dir = store_dir_of(first)?;

    for path in &paths[1..] {
        let candidate = store_dir_of(path)?;
        if candidate != store_dir {
            bail!(
                "cannot generate one static cache for mixed store directories: {store_dir} and {candidate}"
            );
        }
    }

    Ok(store_dir)
}

/// Return the parent (store) directory of a store path.
fn store_dir_of(store_path: &str) -> Result<String> {
    Path::new(store_path)
        .parent()
        .map(|path| path.display().to_string())
        .ok_or_else(|| anyhow::anyhow!("store path has no parent directory: {store_path}"))
}

/// Expand a root path to its runtime closure via `nix-store -qR`, re-rooting
/// every member onto the root's store directory. Falls back to the root
/// alone if the query returns nothing.
fn collect_store_path_closure(store_path: &str, paths: &mut BTreeSet<String>) -> Result<()> {
    let store_dir = store_dir_of(store_path)?;
    let output = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["-qR", store_path])
        .output()
        .with_context(|| format!("running nix-store -qR {store_path}"))?;
    if !output.status.success() {
        bail!(
            "nix-store -qR failed for {store_path}: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }

    let mut found = false;
    for path in String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        paths.insert(re_root_store_path(path, &store_dir)?);
        found = true;
    }

    if !found {
        paths.insert(store_path.to_string());
    }

    Ok(())
}

/// Recursively scan a packages directory for TOML files and harvest their
/// store paths.
fn collect_store_paths_from_dir(dir: &Path, paths: &mut BTreeSet<String>) -> Result<()> {
    for entry in std::fs::read_dir(dir).with_context(|| format!("reading {}", dir.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_store_paths_from_dir(&path, paths)?;
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }
        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let value: TomlValue =
            toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
        collect_store_paths_from_package(&value, paths);
    }
    Ok(())
}

/// Harvest `store_path`, `source_drv`, and sysroot image entries from every
/// version/platform entry of one parsed package TOML document.
fn collect_store_paths_from_package(value: &TomlValue, paths: &mut BTreeSet<String>) {
    let Some(versions) = value.get("versions").and_then(TomlValue::as_array) else {
        return;
    };
    for version in versions {
        let Some(platforms) = version.get("platforms").and_then(TomlValue::as_table) else {
            continue;
        };
        for platform in platforms.values() {
            if let Some(path) = platform.get("store_path").and_then(TomlValue::as_str) {
                paths.insert(path.to_string());
            }
            if let Some(path) = platform.get("source_drv").and_then(TomlValue::as_str)
                && !path.is_empty()
            {
                paths.insert(path.to_string());
            }
            if let Some(images) = platform.get("images").and_then(TomlValue::as_array) {
                for image in images {
                    if let Some(path) = image.get("store_path").and_then(TomlValue::as_str) {
                        paths.insert(path.to_string());
                    }
                }
            }
        }
    }
}

/// Assert that a store path is valid in the local Nix store.
fn check_store_path_valid(path: &str) -> Result<()> {
    let output = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["--check-validity", path])
        .output()
        .with_context(|| format!("running nix-store --check-validity {path}"))?;
    if !output.status.success() {
        bail!("registry store path {path} is not present in the local Nix store");
    }
    Ok(())
}

/// Query NAR metadata for one path via `nix path-info --json`.
fn query_path_info(path: &str) -> Result<CachePathInfo> {
    let output = Command::new("nix")
        .envs(aos_nix_env())
        .args(["path-info", "--json", path])
        .output()
        .with_context(|| format!("running nix path-info on {path}"))?;
    if !output.status.success() {
        bail!(
            "nix path-info failed for {path}: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: JsonValue = serde_json::from_str(&stdout)
        .with_context(|| format!("parsing nix path-info JSON for {path}"))?;
    path_info_from_json(path, &json)
}

/// Convert `nix path-info` JSON into [`CachePathInfo`] for `requested_path`.
///
/// Validates that the reported path's hash matches the request, re-roots the
/// path, references, and deriver onto the requested store directory, and
/// drops self-references.
fn path_info_from_json(requested_path: &str, json: &JsonValue) -> Result<CachePathInfo> {
    let info = select_path_info(json);
    let store_dir = store_dir_of(requested_path)?;
    let requested_hash = store_hash(requested_path);
    let reported_path = info
        .get("path")
        .and_then(JsonValue::as_str)
        .unwrap_or(requested_path);

    if store_hash(reported_path) != requested_hash {
        bail!("nix path-info returned {reported_path} for requested {requested_path}");
    }

    let nar_hash = info
        .get("narHash")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow::anyhow!("nix path-info missing narHash for {requested_path}"))?
        .to_string();
    let nar_size = info
        .get("narSize")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow::anyhow!("nix path-info missing narSize for {requested_path}"))?;
    let path = re_root_store_path(reported_path, &store_dir)?;
    let references = info
        .get("references")
        .and_then(JsonValue::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(JsonValue::as_str)
                .filter(|reference| store_hash(reference) != requested_hash)
                .map(|reference| re_root_store_path(reference, &store_dir))
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let deriver = info
        .get("deriver")
        .or_else(|| info.get("deriverPath"))
        .and_then(JsonValue::as_str)
        .filter(|deriver| !deriver.is_empty())
        .map(|deriver| re_root_store_path(deriver, &store_dir))
        .transpose()?;

    Ok(CachePathInfo {
        path,
        nar_hash,
        nar_size,
        references,
        deriver,
    })
}

/// Rewrite a store path's directory prefix, keeping its basename.
fn re_root_store_path(store_path: &str, store_dir: &str) -> Result<String> {
    let name = basename(store_path);
    if name.is_empty() {
        bail!("store path has no basename: {store_path}");
    }
    Ok(format!("{store_dir}/{name}"))
}

/// Normalize the `nix path-info --json` output shape, which varies across
/// Nix versions: an array of entries, a direct info object, or an object
/// keyed by store path.
fn select_path_info(json: &JsonValue) -> JsonValue {
    if let Some(array) = json.as_array() {
        return array.first().cloned().unwrap_or_else(|| json.clone());
    }
    if let Some(object) = json.as_object() {
        if object.contains_key("path")
            || object.contains_key("narHash")
            || object.contains_key("narSize")
        {
            return json.clone();
        }
        return object
            .values()
            .next()
            .cloned()
            .unwrap_or_else(|| json.clone());
    }
    json.clone()
}

/// Dump a store path as a NAR (`nix-store --dump`) and zstd-compress it.
fn dump_zstd_nar(path: &str) -> Result<Vec<u8>> {
    let output = Command::new("nix-store")
        .envs(aos_nix_env())
        .args(["--dump", path])
        .output()
        .with_context(|| format!("running nix-store --dump {path}"))?;
    if !output.status.success() {
        bail!(
            "nix-store --dump failed for {path}: {}",
            String::from_utf8_lossy(&output.stderr).trim(),
        );
    }
    zstd::stream::encode_all(Cursor::new(output.stdout), 19).context("zstd compressing NAR")
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_core::nar::info as narinfo;
    use tempfile::TempDir;

    #[test]
    fn collect_store_paths_reads_platforms_and_images() {
        let mut paths = BTreeSet::new();
        let value: TomlValue = toml::from_str(
            r#"
[package]
name = "kernel"

[[versions]]
version = "1.0.0"

[versions.platforms.x86_64-linux]
store_path = "/nix/store/root111-kernel"
nar_hash = "sha256:root"
nar_size = 1
source_drv = "/nix/store/src111-kernel-source"
source_nar_hash = "sha256:source"
references = []

[[versions.platforms.x86_64-linux.images]]
format = "qcow2"
store_path = "/nix/store/img111-system-image"
nar_hash = "sha256:image"
nar_size = 2
"#,
        )
        .unwrap();
        collect_store_paths_from_package(&value, &mut paths);
        assert_eq!(
            paths.into_iter().collect::<Vec<_>>(),
            vec![
                "/nix/store/img111-system-image".to_string(),
                "/nix/store/root111-kernel".to_string(),
                "/nix/store/src111-kernel-source".to_string(),
            ]
        );
    }

    #[test]
    fn common_store_dir_accepts_alternate_store_paths() {
        let paths = vec![
            "/tmp/aos-root/store/aaa111-package-a".to_string(),
            "/tmp/aos-root/store/bbb222-package-b".to_string(),
        ];

        assert_eq!(common_store_dir(&paths).unwrap(), "/tmp/aos-root/store");
    }

    #[test]
    fn common_store_dir_rejects_mixed_store_paths() {
        let paths = vec![
            "/tmp/aos-root/store/aaa111-package-a".to_string(),
            "/nix/store/bbb222-package-b".to_string(),
        ];

        let err = common_store_dir(&paths).unwrap_err().to_string();
        assert!(err.contains("mixed store directories"));
    }

    #[test]
    fn re_root_store_path_uses_requested_store_dir() {
        assert_eq!(
            re_root_store_path("/nix/store/aaa111-package-a", "/tmp/aos-root/store").unwrap(),
            "/tmp/aos-root/store/aaa111-package-a",
        );
    }

    #[test]
    fn path_info_from_json_preserves_requested_alternate_store_path() {
        let json = serde_json::json!({
            "path": "/nix/store/aaa111-package-a",
            "narHash": "sha256-test",
            "narSize": 123,
            "references": [
                "/nix/store/aaa111-package-a",
                "/nix/store/bbb222-library-b"
            ],
            "deriver": "/nix/store/ccc333-package-a.drv"
        });

        let info = path_info_from_json("/tmp/aos-root/store/aaa111-package-a", &json).unwrap();

        assert_eq!(info.path, "/tmp/aos-root/store/aaa111-package-a");
        assert_eq!(info.nar_hash, "sha256-test");
        assert_eq!(info.nar_size, 123);
        assert_eq!(
            info.references,
            vec!["/tmp/aos-root/store/bbb222-library-b"],
        );
        assert_eq!(
            info.deriver.as_deref(),
            Some("/tmp/aos-root/store/ccc333-package-a.drv"),
        );
    }

    #[test]
    fn path_info_from_json_rejects_mismatched_reported_path() {
        let json = serde_json::json!({
            "path": "/nix/store/zzz999-package-a",
            "narHash": "sha256-test",
            "narSize": 123,
        });

        let err = path_info_from_json("/tmp/aos-root/store/aaa111-package-a", &json).unwrap_err();
        assert!(err.to_string().contains("nix path-info returned"));
    }

    #[test]
    fn upsert_registry_cache_adds_and_updates_entry() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(
            tmp.path().join("registry.toml"),
            r#"[registry]
name = "test"
"#,
        )
        .unwrap();

        assert!(upsert_registry_cache(tmp.path(), "https://cache.example", 100).unwrap());
        assert!(!upsert_registry_cache(tmp.path(), "https://cache.example", 100).unwrap());
        assert!(upsert_registry_cache(tmp.path(), "https://cache.example", 200).unwrap());

        let content = std::fs::read_to_string(tmp.path().join("registry.toml")).unwrap();
        assert!(content.contains("[[caches]]"));
        assert!(content.contains("url = \"https://cache.example\""));
        assert!(content.contains("priority = 200"));
    }

    #[tokio::test]
    async fn upload_static_cache_to_all_writes_each_filesystem_destination() {
        let source = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let printer = Printer::new(0, true, false);

        std::fs::create_dir_all(source.path().join("nar")).unwrap();
        std::fs::write(
            source.path().join("nix-cache-info"),
            nix_cache_info("/nix/store", 37),
        )
        .unwrap();
        std::fs::write(
            source.path().join("abc123.narinfo"),
            "StorePath: /nix/store/abc123-pkg\n",
        )
        .unwrap();
        std::fs::write(
            source.path().join("nar").join("abc123.nar.zst"),
            b"nar-bytes",
        )
        .unwrap();

        let upload_urls = vec![
            format!("file://{}", first.path().display()),
            format!("file://{}", second.path().display()),
        ];
        upload_static_cache_to_all(
            source.path(),
            &upload_urls,
            &AuthOptions::default(),
            &printer,
        )
        .await
        .unwrap();

        for dest in [first.path(), second.path()] {
            assert!(dest.join("nix-cache-info").exists());
            assert_eq!(
                std::fs::read_to_string(dest.join("nix-cache-info")).unwrap(),
                nix_cache_info("/nix/store", 37),
            );
            assert_eq!(
                std::fs::read_to_string(dest.join("abc123.narinfo")).unwrap(),
                "StorePath: /nix/store/abc123-pkg\n"
            );
            assert_eq!(
                std::fs::read(dest.join("nar").join("abc123.nar.zst")).unwrap(),
                b"nar-bytes"
            );
        }
    }

    #[tokio::test]
    async fn static_cache_upload_preserves_narinfo_url_object_path() {
        let source = TempDir::new().unwrap();
        let dest = TempDir::new().unwrap();
        let printer = Printer::new(0, true, false);
        let store_path = "/nix/store/abc123-package";
        let nar_hash = "sha256:def456";
        let nar_url = nar_url(store_path, nar_hash, NarCompression::Zstd);

        std::fs::create_dir_all(source.path().join("nar")).unwrap();
        std::fs::write(
            source.path().join("nix-cache-info"),
            nix_cache_info("/nix/store", 40),
        )
        .unwrap();
        std::fs::write(
            source.path().join("abc123.narinfo"),
            render_static_narinfo(
                &StaticNarInfoInput {
                    store_path,
                    nar_hash,
                    nar_size: 5,
                    references: &[],
                    deriver: None,
                    signatures: &[],
                    file_hash: "sha256:0123456789abcdef",
                    file_size: 9,
                    compression: NarCompression::Zstd,
                },
                "/nix/store",
                None,
            ),
        )
        .unwrap();
        std::fs::write(source.path().join(&nar_url), b"nar-bytes").unwrap();

        upload_static_cache(
            source.path(),
            &format!("file://{}", dest.path().display()),
            &AuthOptions::default(),
            &printer,
        )
        .await
        .unwrap();

        let uploaded_narinfo = std::fs::read_to_string(dest.path().join("abc123.narinfo")).unwrap();
        let parsed = narinfo::parse(&uploaded_narinfo).unwrap();
        assert_eq!(parsed.url, "nar/abc123-sha256-def456.nar.zst");
        assert_eq!(parsed.url, nar_url);
        assert_eq!(
            std::fs::read(dest.path().join(parsed.url)).unwrap(),
            b"nar-bytes",
        );
    }

    #[tokio::test]
    async fn upload_static_cache_to_all_reports_partial_failures() {
        let source = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let printer = Printer::new(0, true, false);

        std::fs::create_dir_all(source.path().join("nar")).unwrap();
        std::fs::write(
            source.path().join("nix-cache-info"),
            nix_cache_info("/nix/store", 40),
        )
        .unwrap();
        std::fs::write(
            source.path().join("abc123.narinfo"),
            "StorePath: /nix/store/abc123-pkg\n",
        )
        .unwrap();

        let upload_urls = vec![
            format!("file://{}", first.path().display()),
            "not-a-url".to_string(),
            format!("file://{}", second.path().display()),
        ];
        let err = upload_static_cache_to_all(
            source.path(),
            &upload_urls,
            &AuthOptions::default(),
            &printer,
        )
        .await
        .unwrap_err();

        let message = format!("{err:#}");
        assert!(message.contains("static cache upload failed for 1/3 destination"));
        assert!(message.contains("not-a-url"));
        for dest in [first.path(), second.path()] {
            assert!(dest.join("nix-cache-info").exists());
            assert!(dest.join("abc123.narinfo").exists());
        }
    }
}
