//! Committed registry manifests and consumer mirror priority resolution.

use anyhow::{Context, Result};
use aos_registry_format::consumer::{CacheEntry, RegistryConfig, RegistryRootConfig};
use std::path::Path;

/// Reads and parses the committed registry manifest.
///
/// # Errors
///
/// Returns an error when an existing manifest cannot be read or parsed.
pub fn read_registry_toml(dir: &Path) -> Result<Option<RegistryRootConfig>> {
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
pub fn resolve_mirrors_for_registry(dir: &Path, registry: &RegistryConfig) -> Vec<CacheEntry> {
    let mut caches = registry.caches.clone();
    caches.extend(resolve_mirrors(dir));
    caches.sort_by(|a, b| b.priority.cmp(&a.priority));
    caches
}
