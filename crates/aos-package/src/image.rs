//! Consumer-side image commands (`apm image`).
//!
//! Lists, shows, and downloads pre-built system images from registries.

use std::path::Path;

use anyhow::{bail, Context, Result};

use aos_core::output::Printer;

use crate::config::ApmConfig;
use crate::download::{download_nars, DownloadRequest};
use crate::registry_ops::resolve_mirrors;
use crate::types::{ImageMeta, ImageToml};
use crate::ImageCommand;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run an `apm image` subcommand.
pub async fn run(
    command: &ImageCommand,
    config: &ApmConfig,
    printer: &Printer,
) -> Result<()> {
    match command {
        ImageCommand::List {
            registry,
            platform,
            format,
        } => list(config, registry.as_deref(), platform.as_deref(), format, printer).await,
        ImageCommand::Show { name, version } => {
            show(config, name, version.as_deref(), printer).await
        }
        ImageCommand::Pull {
            name,
            version,
            platform,
            output,
            verify,
        } => {
            pull(
                config,
                name,
                version.as_deref(),
                platform.as_deref(),
                output.as_deref(),
                *verify,
                printer,
            )
            .await
        }
        ImageCommand::Definition {
            name,
            version,
            output,
        } => definition(config, name, version.as_deref(), output.as_deref(), printer).await,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Default platform string.
#[allow(dead_code)]
fn default_platform() -> String {
    "x86_64-linux".to_string()
}

/// Find and parse all image TOML files in the registry cache.
fn find_images(
    cache_dir: &Path,
    registry_name: &str,
    platform: Option<&str>,
) -> Result<Vec<(String, ImageMeta)>> {
    let images_dir = cache_dir.join(registry_name).join("images");
    if !images_dir.is_dir() {
        return Ok(Vec::new());
    }

    let plat = platform.unwrap_or("x86_64-linux");
    let mut results = Vec::new();

    for letter_entry in std::fs::read_dir(&images_dir)?.flatten() {
        if !letter_entry.path().is_dir() {
            continue;
        }
        for entry in std::fs::read_dir(letter_entry.path())?.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "toml").unwrap_or(false) {
                let content = std::fs::read_to_string(&path)?;
                if let Ok(img) = toml::from_str::<ImageToml>(&content) {
                    for ver in &img.versions {
                        if let Some(plat_entry) = ver.platforms.get(plat) {
                            let meta = ImageMeta {
                                name: img.image.name.clone(),
                                version: ver.version.clone(),
                                description: img
                                    .image
                                    .description
                                    .clone()
                                    .unwrap_or_default(),
                                maintainer: img
                                    .image
                                    .maintainer
                                    .clone()
                                    .unwrap_or_default(),
                                definition: ver.definition.clone(),
                                platform: plat.to_string(),
                                store_path: plat_entry.store_path.clone(),
                                nar_hash: plat_entry.nar_hash.clone(),
                                nar_size: plat_entry.nar_size,
                                download_hash: plat_entry.download_hash.clone(),
                                download_size: plat_entry.download_size,
                                references: plat_entry.references.clone(),
                                closure_size: plat_entry.closure_size,
                            };
                            results.push((registry_name.to_string(), meta));
                        }
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Resolve mirror URL for a registry (try registry.toml first).
fn resolve_mirror_url(config: &ApmConfig, registry_name: &str) -> String {
    let registries_dir = config.scope.registries_path().join(registry_name);
    let mirrors = resolve_mirrors(&registries_dir);

    if let Some(cache) = mirrors.first() {
        return cache.url.clone();
    }

    // Fallback: find registry config and use URL-based mirror.
    if let Some((cfg, _)) = config.find_registry(registry_name) {
        let base = cfg.url.trim_end_matches('/');
        return format!("{base}/nar");
    }

    format!("https://cache.aos.dev/{registry_name}/nar")
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// `apm image list`
async fn list(
    config: &ApmConfig,
    registry: Option<&str>,
    platform: Option<&str>,
    _format: &str,
    printer: &Printer,
) -> Result<()> {
    let cache_dir = config.cache_path();
    let mut all_images = Vec::new();

    let registries = config.enabled_registries();
    for reg_config in &registries {
        if let Some(filter) = registry {
            if reg_config.name != filter {
                continue;
            }
        }
        match find_images(&cache_dir, &reg_config.name, platform) {
            Ok(images) => all_images.extend(images),
            Err(_) => continue,
        }
    }

    if all_images.is_empty() {
        printer.info("No images found. Run `apm update` to sync registries.");
        return Ok(());
    }

    printer.header(&format!("{} image(s):", all_images.len()));
    for (reg, meta) in &all_images {
        printer.plain(&format!(
            "  {} {} ({}) [{}]",
            meta.name, meta.version, meta.platform, reg,
        ));
        if !meta.description.is_empty() {
            printer.plain(&format!("    {}", meta.description));
        }
    }

    Ok(())
}

/// `apm image show <NAME>`
async fn show(
    config: &ApmConfig,
    name: &str,
    version: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let cache_dir = config.cache_path();
    let mut found = None;

    for reg_config in config.enabled_registries() {
        let images = find_images(&cache_dir, &reg_config.name, None)?;
        for (reg, meta) in images {
            if meta.name == name {
                if let Some(ver) = version {
                    if meta.version != ver {
                        continue;
                    }
                }
                found = Some((reg, meta));
                break;
            }
        }
        if found.is_some() {
            break;
        }
    }

    let (reg, meta) = found.ok_or_else(|| anyhow::anyhow!("image '{name}' not found"))?;

    printer.header(&format!("Image: {}", meta.name));
    printer.kv("Version", &meta.version);
    printer.kv("Platform", &meta.platform);
    printer.kv("Registry", &reg);
    if !meta.description.is_empty() {
        printer.kv("Description", &meta.description);
    }
    if !meta.maintainer.is_empty() {
        printer.kv("Maintainer", &meta.maintainer);
    }
    if let Some(ref def) = meta.definition {
        printer.kv("Definition", def);
    }
    printer.kv("Store path", &meta.store_path);
    printer.kv("NAR hash", &meta.nar_hash);
    printer.kv("NAR size", &format_size(meta.nar_size));
    printer.kv("Download size", &format_size(meta.download_size));
    printer.kv("Closure size", &format_size(meta.closure_size));
    printer.kv("References", &format!("{}", meta.references.len()));

    Ok(())
}

/// `apm image pull <NAME>`
async fn pull(
    config: &ApmConfig,
    name: &str,
    version: Option<&str>,
    platform: Option<&str>,
    _output: Option<&str>,
    _verify: bool,
    printer: &Printer,
) -> Result<()> {
    let cache_dir = config.cache_path();
    let plat = platform.unwrap_or("x86_64-linux");
    let mut found = None;
    let mut found_reg = String::new();

    for reg_config in config.enabled_registries() {
        let images = find_images(&cache_dir, &reg_config.name, Some(plat))?;
        for (reg, meta) in images {
            if meta.name == name {
                if let Some(ver) = version {
                    if meta.version != ver {
                        continue;
                    }
                }
                found_reg = reg;
                found = Some(meta);
                break;
            }
        }
        if found.is_some() {
            break;
        }
    }

    let meta = found.ok_or_else(|| anyhow::anyhow!("image '{name}' not found for {plat}"))?;

    printer.header(&format!(
        "Pulling {} {} ({})...",
        meta.name, meta.version, meta.platform,
    ));

    let mirror_url = resolve_mirror_url(config, &found_reg);
    let request = DownloadRequest {
        store_path: meta.store_path.clone(),
        nar_hash: meta.nar_hash.clone(),
        download_hash: meta.download_hash.clone(),
        download_size: meta.download_size,
        mirror_url,
    };

    let client = reqwest::Client::new();
    let nar_cache = config.nar_cache_path();

    let results = download_nars(
        &client,
        &[request],
        &nar_cache,
        config.settings.parallel_downloads,
        printer,
    )
    .await?;

    if results.is_empty() {
        bail!("download failed");
    }

    printer.success(&format!(
        "Image {} {} downloaded to cache.",
        meta.name, meta.version,
    ));

    Ok(())
}

/// `apm image definition <NAME>`
async fn definition(
    config: &ApmConfig,
    name: &str,
    version: Option<&str>,
    output: Option<&str>,
    printer: &Printer,
) -> Result<()> {
    let cache_dir = config.cache_path();
    let mut found_def = None;

    for reg_config in config.enabled_registries() {
        let images = find_images(&cache_dir, &reg_config.name, None)?;
        for (reg, meta) in images {
            if meta.name == name {
                if let Some(ver) = version {
                    if meta.version != ver {
                        continue;
                    }
                }
                if let Some(ref def) = meta.definition {
                    // Read the definition from the registry cache.
                    let def_path = cache_dir
                        .join(&reg)
                        .join(def);
                    if def_path.exists() {
                        found_def = Some((def_path, meta.version.clone()));
                        break;
                    }
                }
            }
        }
        if found_def.is_some() {
            break;
        }
    }

    let (def_path, ver) = found_def.ok_or_else(|| {
        anyhow::anyhow!("no definition found for image '{name}'")
    })?;

    let content = std::fs::read_to_string(&def_path)
        .with_context(|| format!("reading {}", def_path.display()))?;

    if let Some(out) = output {
        std::fs::write(out, &content)
            .with_context(|| format!("writing to {out}"))?;
        printer.success(&format!("Definition for {name} {ver} written to {out}."));
    } else {
        printer.plain(&content);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Format helpers
// ---------------------------------------------------------------------------

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let kib = bytes as f64 / 1024.0;
    if kib < 1024.0 {
        return format!("{kib:.1} KiB");
    }
    let mib = kib / 1024.0;
    if mib < 1024.0 {
        return format!("{mib:.1} MiB");
    }
    let gib = mib / 1024.0;
    format!("{gib:.1} GiB")
}
