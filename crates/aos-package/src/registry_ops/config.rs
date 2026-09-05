//! Registry selection, committed configuration, upload defaults, and display formatting.
//!
//! Reads the registry header and configured cache destinations. A minimal header is:
//!
//! ```toml
//! [registry]
//! name = "example"
//! ```

use crate::config::ApmConfig;
use crate::registry::nixcache;
use crate::types::{CacheEntry, RegistryRootConfig, validate_registry_name};
use anyhow::{Context, Result, bail};
use aos_core::output::Printer;
use std::path::{Path, PathBuf};

/// Resolve the registry storage directory for a given registry name.
pub(in crate::registry_ops) fn registry_dir(
    config: &ApmConfig,
    registry: Option<&str>,
) -> Result<PathBuf> {
    let name = resolve_registry_name(config, registry)?;
    Ok(config.scope.registries_path().join(&name))
}

/// Resolve which registry to operate on.
///
/// If `registry` is specified, use it. Otherwise, if there is exactly one
/// registry, use it. Otherwise bail with an error.
pub(in crate::registry_ops) fn resolve_registry_name(
    config: &ApmConfig,
    registry: Option<&str>,
) -> Result<String> {
    if let Some(name) = registry {
        validate_registry_name(name)?;
        return Ok(name.to_string());
    }

    // Check the registries storage directory for available clones.
    let registries_path = config.scope.registries_path();
    if registries_path.is_dir() {
        let mut names: Vec<String> = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&registries_path) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    if let Some(name) = entry.file_name().to_str() {
                        if validate_registry_name(name).is_ok() {
                            names.push(name.to_string());
                        }
                    }
                }
            }
        }
        if names.len() == 1 {
            return names
                .into_iter()
                .next()
                .context("single discovered registry name disappeared");
        }
        if names.len() > 1 {
            bail!(
                "multiple registries found ({}). Use --registry to specify one.",
                names.join(", ")
            );
        }
    }

    // Fall back to configured registries.
    if config.registries.len() == 1 {
        return Ok(config.registries[0].0.name.clone());
    }
    if config.registries.is_empty() {
        bail!("no registries configured. Add one with `apr create <name>` or `apr add <url>`.");
    }
    let names: Vec<&str> = config
        .registries
        .iter()
        .map(|(c, _)| c.name.as_str())
        .collect();
    bail!(
        "multiple registries configured ({}). Use --registry to specify one.",
        names.join(", ")
    );
}

/// Read and parse registry.toml from a registry directory.
pub(in crate::registry_ops) fn read_registry_toml(
    dir: &Path,
) -> Result<Option<RegistryRootConfig>> {
    let path = dir.join("registry.toml");
    if !path.exists() {
        return Ok(None);
    }
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let config: RegistryRootConfig =
        toml::from_str(&content).with_context(|| format!("parsing {}", path.display()))?;
    Ok(Some(config))
}

/// Whether a registry records content addresses in its `store/` graph
/// (`[registry] content_addressed`, RFC-0005). Defaults to `true` when the
/// file is missing or unparsable.
pub(in crate::registry_ops) fn registry_content_addressed(dir: &Path) -> bool {
    match read_registry_toml(dir) {
        Ok(Some(config)) => config.registry.content_addressed,
        _ => true,
    }
}

/// Resolves the mirror cache URLs committed in a registry's `registry.toml`.
///
/// Flattens the committed `[caches]` cache stack and returns the entries sorted
/// by descending priority, or an empty
/// list when the file is missing, unparsable, or lists no caches.
pub fn resolve_mirrors(dir: &Path) -> Vec<CacheEntry> {
    match read_registry_toml(dir) {
        Ok(Some(config)) => {
            let mut caches = config.cache_entries();
            caches.sort_by(|a, b| b.priority.cmp(&a.priority));
            caches
        }
        _ => Vec::new(),
    }
}

/// Resolves mirror cache URLs from the committed `registry.toml` plus the
/// consumer's client-side cache overrides.
///
/// The client-configured caches from `registries.d` are merged with the
/// committed entries and the combined list is sorted by descending
/// priority.
pub fn resolve_mirrors_for_registry(
    dir: &Path,
    registry: &crate::types::RegistryConfig,
) -> Vec<CacheEntry> {
    let mut caches = registry.caches.clone();
    caches.extend(resolve_mirrors(dir));
    caches.sort_by(|a, b| b.priority.cmp(&a.priority));
    caches
}

pub(in crate::registry_ops) fn configured_registry_names(config: &ApmConfig) -> Vec<String> {
    config
        .registries
        .iter()
        .map(|(registry, _)| registry.name.clone())
        .collect()
}

pub(in crate::registry_ops) fn registry_upload_auth_config<'a>(
    config: &'a ApmConfig,
    registry_name: &str,
) -> Option<&'a crate::types::RegistryUploadAuthConfig> {
    config
        .registries
        .iter()
        .find(|(registry, _state)| registry.name == registry_name)
        .and_then(|(registry, _state)| registry.upload_auth.as_ref())
}

pub(in crate::registry_ops) fn registry_cache_max_age_days(
    config: &ApmConfig,
    registry_name: &str,
) -> u64 {
    config
        .registries
        .iter()
        .find(|(registry, _state)| registry.name == registry_name)
        .map(|(registry, _state)| registry.cache.max_age_days())
        .unwrap_or(crate::types::DEFAULT_REGISTRY_CACHE_MAX_AGE_DAYS)
}

pub(in crate::registry_ops) fn warn_on_cache_gc(
    cache_dir: &Path,
    max_age_days: u64,
    printer: &Printer,
) {
    if let Err(err) = nixcache::gc_static_cache(cache_dir, max_age_days, false) {
        printer.warning(&format!(
            "Static cache GC failed for {}: {err:#}",
            cache_dir.display()
        ));
    }
}

/// Resolve upload destinations: `--upload-url` flags when given, otherwise
/// the `upload_urls` persisted in `[registry.upload_auth]` by
/// `apr origin config`.
pub(in crate::registry_ops) fn resolve_upload_urls(
    config: &ApmConfig,
    registry_name: &str,
    flag_urls: &[String],
) -> Vec<String> {
    if !flag_urls.is_empty() {
        return flag_urls.to_vec();
    }
    registry_upload_auth_config(config, registry_name)
        .map(|upload| upload.upload_urls.clone())
        .unwrap_or_default()
}

pub(in crate::registry_ops) fn resolve_effective_release_cache_url(
    explicit_cache_url: Option<&str>,
    upload_urls: &[String],
    has_store_roots: bool,
) -> Result<Option<String>> {
    if let Some(cache_url) = explicit_cache_url {
        return Ok(Some(cache_url.to_string()));
    }
    if upload_urls.is_empty() || !has_store_roots {
        return Ok(None);
    }

    let http_urls = upload_urls
        .iter()
        .filter(|url| {
            url::Url::parse(url)
                .map(|parsed| matches!(parsed.scheme(), "http" | "https"))
                .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    if upload_urls.len() == 1 && http_urls.len() == 1 {
        return Ok(Some(http_urls[0].to_string()));
    }

    bail!(
        "publishing a release with store paths requires --cache-url unless exactly one upload URL is http(s)"
    );
}

pub(in crate::registry_ops) fn format_size(bytes: u64) -> String {
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

#[cfg(test)]
mod tests;
