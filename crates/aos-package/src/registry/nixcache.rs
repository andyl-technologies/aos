//! Static Nix binary-cache generation for registry store paths.

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
use aos_core::nar::info::store_hash;
use aos_core::nix::aos_nix_env;
use aos_core::output::Printer;
use serde_json::Value as JsonValue;
use sha2::{Digest, Sha256};
use toml::Value as TomlValue;

#[derive(Debug, Clone)]
pub struct StaticCacheReport {
    pub paths: usize,
    pub narinfos: usize,
    pub nars: usize,
    pub output_dir: PathBuf,
}

#[derive(Debug, Clone)]
struct CachePathInfo {
    path: String,
    nar_hash: String,
    nar_size: u64,
    references: Vec<String>,
    deriver: Option<String>,
}

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

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating {}", output_dir.display()))?;
    std::fs::create_dir_all(output_dir.join("nar"))
        .with_context(|| format!("creating {}", output_dir.join("nar").display()))?;
    std::fs::write(
        output_dir.join("nix-cache-info"),
        nix_cache_info("/nix/store", priority),
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
            "/nix/store",
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

pub async fn upload_static_cache(
    output_dir: &Path,
    upload_url: &str,
    printer: &Printer,
) -> Result<()> {
    let cache = backend::from_url(upload_url, &AuthOptions::default()).await?;
    cache.ensure_cache_info("/nix/store").await?;

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

pub async fn upload_static_cache_to_all(
    output_dir: &Path,
    upload_urls: &[String],
    printer: &Printer,
) -> Result<()> {
    let mut failures = Vec::new();

    for upload_url in upload_urls {
        if let Err(err) = upload_static_cache(output_dir, upload_url, printer).await {
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

fn collect_store_paths(registry_dir: &Path) -> Result<Vec<String>> {
    let packages = registry_dir.join("packages");
    let mut paths = BTreeSet::new();
    if !packages.exists() {
        return Ok(Vec::new());
    }
    collect_store_paths_from_dir(&packages, &mut paths)?;
    Ok(paths.into_iter().collect())
}

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
    let info = select_path_info(&json);

    let nar_hash = info
        .get("narHash")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| anyhow::anyhow!("nix path-info missing narHash for {path}"))?
        .to_string();
    let nar_size = info
        .get("narSize")
        .and_then(JsonValue::as_u64)
        .ok_or_else(|| anyhow::anyhow!("nix path-info missing narSize for {path}"))?;
    let path = info
        .get("path")
        .and_then(JsonValue::as_str)
        .unwrap_or(path)
        .to_string();
    let references = info
        .get("references")
        .and_then(JsonValue::as_array)
        .map(|refs| {
            refs.iter()
                .filter_map(JsonValue::as_str)
                .filter(|reference| *reference != path.as_str())
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let deriver = info
        .get("deriver")
        .or_else(|| info.get("deriverPath"))
        .and_then(JsonValue::as_str)
        .filter(|deriver| !deriver.is_empty())
        .map(ToString::to_string);

    Ok(CachePathInfo {
        path,
        nar_hash,
        nar_size,
        references,
        deriver,
    })
}

fn select_path_info(json: &JsonValue) -> JsonValue {
    if let Some(array) = json.as_array() {
        return array.first().cloned().unwrap_or_else(|| json.clone());
    }
    if let Some(object) = json.as_object() {
        return object
            .values()
            .next()
            .cloned()
            .unwrap_or_else(|| json.clone());
    }
    json.clone()
}

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
source_nar_hash = ""
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
            ]
        );
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
        upload_static_cache_to_all(source.path(), &upload_urls, &printer)
            .await
            .unwrap();

        for dest in [first.path(), second.path()] {
            assert!(dest.join("nix-cache-info").exists());
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
    async fn upload_static_cache_to_all_reports_partial_failures() {
        let source = TempDir::new().unwrap();
        let good = TempDir::new().unwrap();
        let printer = Printer::new(0, true, false);

        std::fs::create_dir_all(source.path().join("nar")).unwrap();
        std::fs::write(
            source.path().join("abc123.narinfo"),
            "StorePath: /nix/store/abc123-pkg\n",
        )
        .unwrap();

        let upload_urls = vec![
            "not-a-url".to_string(),
            format!("file://{}", good.path().display()),
        ];
        let err = upload_static_cache_to_all(source.path(), &upload_urls, &printer)
            .await
            .unwrap_err();

        let message = format!("{err:#}");
        assert!(message.contains("static cache upload failed for 1/2 destination"));
        assert!(message.contains("not-a-url"));
        assert!(good.path().join("abc123.narinfo").exists());
    }
}
