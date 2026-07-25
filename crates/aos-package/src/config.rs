//! Loading apm configuration from disk.
//!
//! Configuration is assembled from an ordered list of **layers** (lowest to
//! highest precedence), reported by [`ProfileScope::config_layers`]:
//!
//! - **System**: `[/etc/apm, /var/lib/apm/config]`.
//! - **User**: `[/etc/apm, /var/lib/apm/config, ~/.config/apm]`.
//!
//! `/etc/apm` is a read-only image *seed* (its tmpfs `/etc` upper is discarded
//! on reboot); `/var/lib/apm/config` is the persistent *writable* layer where
//! `apm` records runtime config and sync state. Each layer holds the same
//! shape: an `apm.conf` and a `registries.d/` directory of per-registry TOML
//! files.
//!
//! Layers merge **field by field**, not wholesale:
//!
//! - A registry's identity is its file name (`registries.d/<stem>.toml`), not
//!   a TOML field. Files of the same stem across layers are deep-merged: nested
//!   tables (`[registry.signing]`, `[registry.state]`, …) merge key by key,
//!   scalars in a higher layer override the lower one, and arrays concatenate
//!   (lower-layer entries first). The same deep-merge applies to `[settings]`
//!   in `apm.conf`.
//! - This lets a writable-layer file be a **minimal delta**: an `apm update`
//!   fragment is just `[registry.state]`, an `enable`/`disable` toggle is just
//!   `enabled = …`, and a seeded registry's `url`/signing keep inheriting from
//!   `/etc`.
//!
//! Robustness rules keep one bad layer from failing the whole invocation: an
//! empty or `[registry]`-less file is skipped (this is how blanking an `/etc`
//! seed removes a registry), a malformed or unreadable file is warned about and
//! skipped, and a merged registry that still lacks a `url` is an orphaned
//! override that is dropped (and becomes prune-eligible — see [`crate::clean`]).

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::types::{
    ApmConfFile, ApmSettings, CacheEntry, ProfileScope, RegistryConfig, RegistryFile,
    RegistryState, validate_registry_name,
};

/// Loaded APM configuration for the current session.
#[derive(Debug, Clone)]
pub struct ApmConfig {
    /// Global settings from `apm.conf` (or defaults when absent).
    pub settings: ApmSettings,
    /// All configured registries with their last-sync state, sorted by
    /// priority descending. Includes disabled registries; use
    /// [`ApmConfig::enabled_registries`] to filter.
    pub registries: Vec<(RegistryConfig, Option<RegistryState>)>,
    /// The profile scope (user or system) this configuration was loaded for.
    pub scope: ProfileScope,
}

impl ApmConfig {
    /// Load configuration for the given scope.
    ///
    /// Reads every layer of [`ProfileScope::config_layers`] and merges them
    /// field by field (see the module docs). Missing files are not errors:
    /// absent settings fall back to [`ApmSettings::default`], and absent
    /// `registries.d/` directories contribute nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if the merged `[settings]` are invalid, or if a merged
    /// registry config sets a `name` that disagrees with its file stem or has
    /// a stem that is not a valid registry name. Individual malformed or
    /// unreadable layer files are skipped with a warning rather than failing
    /// the load.
    pub fn load(scope: ProfileScope) -> Result<Self> {
        let layers = scope.config_layers();
        let settings = Self::load_settings(&layers)?;
        let registries = Self::load_registries(&layers)?;

        Ok(Self {
            settings,
            registries,
            scope,
        })
    }

    /// Load and deep-merge `apm.conf` `[settings]` across all layers.
    ///
    /// Each layer's `apm.conf` is parsed as a [`toml::Value`] and merged into
    /// the accumulator in precedence order, so a higher layer overrides
    /// individual fields of a lower one. A malformed or unreadable `apm.conf`
    /// is skipped with a warning. When no layer defines settings, the defaults
    /// apply.
    fn load_settings(layers: &[PathBuf]) -> Result<ApmSettings> {
        let mut merged: Option<toml::Value> = None;
        for layer in layers {
            let path = layer.join("apm.conf");
            if !path.exists() {
                continue;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(err) => {
                    eprintln!("warning: skipping unreadable {}: {err}", path.display());
                    continue;
                }
            };
            match toml::from_str::<toml::Value>(&content) {
                Ok(value) => match merged.as_mut() {
                    Some(base) => deep_merge(base, value),
                    None => merged = Some(value),
                },
                Err(err) => {
                    eprintln!("warning: skipping malformed {}: {err}", path.display());
                }
            }
        }

        let settings = match merged {
            Some(value) => {
                let conf: ApmConfFile = value
                    .try_into()
                    .context("deserializing merged apm.conf settings")?;
                conf.settings
            }
            None => ApmSettings::default(),
        };
        Self::validate_settings(&settings)?;
        Ok(settings)
    }

    /// Validate the merged `apm.conf` settings before command dispatch.
    ///
    /// # Errors
    ///
    /// Returns an error when `[settings].parallel_downloads` is zero or the
    /// credential PCR public key path is relative.
    fn validate_settings(settings: &ApmSettings) -> Result<()> {
        if settings.parallel_downloads == 0 {
            anyhow::bail!("apm.conf: [settings].parallel_downloads must be at least 1");
        }
        if let Some(path) = &settings.credential_pcr_public_key
            && !Path::new(path).is_absolute()
        {
            anyhow::bail!(
                "apm.conf: [settings].credential_pcr_public_key must be an absolute path"
            );
        }

        Ok(())
    }

    /// Scan every layer's `registries.d/` and deep-merge per file stem.
    ///
    /// Files sharing a stem across layers are merged lowest-to-highest into a
    /// single registry; see the module docs for the merge and robustness
    /// rules. The result is sorted by priority, highest first.
    fn load_registries(layers: &[PathBuf]) -> Result<Vec<(RegistryConfig, Option<RegistryState>)>> {
        // Collect, per file stem, the ordered list of file values from each
        // layer that defines it (lowest precedence first). A `BTreeMap` keeps
        // iteration deterministic.
        let mut by_stem: BTreeMap<String, Vec<toml::Value>> = BTreeMap::new();
        for layer in layers {
            let dir = layer.join("registries.d");
            if dir.is_dir() {
                Self::collect_registry_layer(&dir, &mut by_stem)?;
            }
        }

        let mut registries = Vec::new();
        for (stem, fragments) in by_stem {
            if let Some(entry) = Self::merge_registry_fragments(&stem, fragments)? {
                registries.push(entry);
            }
        }
        // Sort by priority descending (highest priority first).
        registries.sort_by(|a, b| b.0.priority.cmp(&a.0.priority));

        Ok(registries)
    }

    /// Read one layer's `registries.d/` directory, appending each non-blank
    /// file's parsed value under its stem.
    ///
    /// Empty files and files without a non-empty `[registry]` table are
    /// skipped silently (this is how blanking an `/etc` seed removes a
    /// registry). Malformed or unreadable files are skipped with a warning.
    fn collect_registry_layer(
        dir: &Path,
        by_stem: &mut BTreeMap<String, Vec<toml::Value>>,
    ) -> Result<()> {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("reading {}", dir.display()))?
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "toml")
                    .unwrap_or(false)
            })
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            let path = entry.path();
            let Some(stem) = path.file_stem().and_then(|s| s.to_str()).map(str::to_owned) else {
                continue;
            };
            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(err) => {
                    eprintln!(
                        "warning: skipping unreadable registry config {}: {err}",
                        path.display()
                    );
                    continue;
                }
            };
            let value: toml::Value = match toml::from_str(&content) {
                Ok(value) => value,
                Err(err) => {
                    eprintln!(
                        "warning: skipping malformed registry config {}: {err}",
                        path.display()
                    );
                    continue;
                }
            };
            // A blank or `[registry]`-less file is an intentionally emptied
            // seed: ignore it rather than treating it as a definition.
            let has_registry = value
                .get("registry")
                .and_then(toml::Value::as_table)
                .is_some_and(|table| !table.is_empty());
            if !has_registry {
                continue;
            }
            by_stem.entry(stem).or_default().push(value);
        }

        Ok(())
    }

    /// Deep-merge a stem's layered file values into a single registry config.
    ///
    /// Returns `Ok(None)` when the fragments merge to an orphaned override —
    /// one with no `url`, whose defining layer is gone — which is dropped with
    /// a warning so it cannot resurrect stale sync state.
    ///
    /// # Errors
    ///
    /// Returns an error when the merged value sets a `name` that disagrees with
    /// `stem`, when `stem` is not a valid registry name, or when the merged
    /// value cannot be deserialized into a [`RegistryFile`].
    fn merge_registry_fragments(
        stem: &str,
        fragments: Vec<toml::Value>,
    ) -> Result<Option<(RegistryConfig, Option<RegistryState>)>> {
        let mut merged: Option<toml::Value> = None;
        for fragment in fragments {
            match merged.as_mut() {
                Some(base) => deep_merge(base, fragment),
                None => merged = Some(fragment),
            }
        }
        let Some(merged) = merged else {
            return Ok(None);
        };

        let rf: RegistryFile = merged
            .try_into()
            .with_context(|| format!("deserializing merged registry config '{stem}'"))?;
        let inner = rf.registry;

        // Identity is the file stem; an explicit `name` must agree with it.
        if let Some(name) = inner.name.as_deref()
            && name != stem
        {
            anyhow::bail!(
                "registry config '{stem}.toml' sets name = \"{name}\"; \
                 the name must match the file stem"
            );
        }
        validate_registry_name(stem)
            .with_context(|| format!("validating registry name '{stem}'"))?;

        // No url after merging means the defining layer is gone: drop the
        // orphaned override (it becomes prune-eligible via `apm gc`).
        let Some(url) = inner.url else {
            eprintln!(
                "warning: ignoring registry '{stem}': no url after merging config layers \
                 (orphaned override)"
            );
            return Ok(None);
        };

        let mut caches = inner.caches;
        dedupe_caches(&mut caches);
        let mut upload_auth = inner.upload_auth;
        if let Some(auth) = upload_auth.as_mut() {
            dedupe_strings(&mut auth.upload_urls);
        }

        let config = RegistryConfig {
            name: stem.to_string(),
            url,
            priority: inner.priority,
            enabled: inner.enabled,
            commit: inner.commit,
            branch: inner.branch,
            channel: inner.channel,
            tag: inner.tag,
            version: inner.version,
            pin: inner.pin,
            max_staleness_seconds: inner.max_staleness_seconds,
            caches,
            cache: inner.cache,
            upload_auth,
            signing_keys: inner.signing_keys,
            signing: inner.signing,
        };

        Ok(Some((config, inner.state)))
    }

    /// Return the profile base path for this session's scope.
    pub fn profile_path(&self) -> PathBuf {
        self.scope.profile_path()
    }

    /// Return the registry cache path for this session's scope.
    pub fn cache_path(&self) -> PathBuf {
        self.scope.cache_path()
    }

    /// Return the NAR download cache path.
    pub fn nar_cache_path(&self) -> PathBuf {
        self.scope.nar_cache_path()
    }

    /// Return the internal static-cache staging path for `registry`.
    pub fn registry_cache_path(&self, registry: &str) -> PathBuf {
        self.scope.registry_cache_path(registry)
    }

    /// Return registries sorted by priority (highest first), only enabled
    /// ones.
    pub fn enabled_registries(&self) -> Vec<&RegistryConfig> {
        self.registries
            .iter()
            .filter(|(cfg, _)| cfg.enabled)
            .map(|(cfg, _)| cfg)
            .collect()
    }

    /// Find a registry (and its sync state) by name, enabled or not.
    pub fn find_registry(&self, name: &str) -> Option<&(RegistryConfig, Option<RegistryState>)> {
        self.registries.iter().find(|(cfg, _)| cfg.name == name)
    }

    /// Return the registry config file to mutate for `name`.
    ///
    /// Return the writable-layer overlay file for `name`.
    ///
    /// Consumer mutations — `apm update` sync state and `registry`
    /// `enable`/`disable` — write a minimal delta here: always
    /// [`ProfileScope::writable_config_dir`] (`/var/lib/apm/config` for system
    /// scope), never the read-only `/etc/apm` seed. The file may not exist yet
    /// (callers create it); for a seeded registry the delta merges over the
    /// seed, so url/signing keep inheriting from `/etc`.
    pub fn registry_overlay_path(&self, name: &str) -> PathBuf {
        self.scope
            .writable_config_dir()
            .join("registries.d")
            .join(format!("{name}.toml"))
    }

    /// Return the existing config file a producer command edits in place.
    ///
    /// Unlike [`ApmConfig::registry_overlay_path`] (which always targets the
    /// writable overlay), the `apr` maintainer commands (`origin config`,
    /// `keys generate`/`register`) edit a registry's *definition* where it
    /// already lives: the user file when present, otherwise a writable system
    /// config file when the registry came only from system config. If neither
    /// exists this returns the primary path so callers can report a precise
    /// missing-config error.
    pub fn registry_config_path_for_update(&self, name: &str) -> PathBuf {
        let primary = self
            .scope
            .config_dir()
            .join("registries.d")
            .join(format!("{name}.toml"));
        if primary.exists() || self.scope != ProfileScope::User {
            return primary;
        }

        let fallback = ProfileScope::System
            .config_dir()
            .join("registries.d")
            .join(format!("{name}.toml"));
        if fallback.exists()
            && std::fs::OpenOptions::new()
                .write(true)
                .open(&fallback)
                .is_ok()
        {
            fallback
        } else {
            primary
        }
    }
}

/// Recursively merge `overlay` into `base`, with `overlay` taking precedence.
///
/// - Two tables merge key by key, recursing into shared keys.
/// - Two arrays concatenate, with `base` (lower-layer) entries first.
/// - Any other pairing replaces `base` with `overlay`, so a scalar in a higher
///   layer overrides the lower layer's value.
fn deep_merge(base: &mut toml::Value, overlay: toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base_table), toml::Value::Table(overlay_table)) => {
            for (key, value) in overlay_table {
                match base_table.get_mut(&key) {
                    Some(slot) => deep_merge(slot, value),
                    None => {
                        base_table.insert(key, value);
                    }
                }
            }
        }
        (toml::Value::Array(base_array), toml::Value::Array(overlay_array)) => {
            base_array.extend(overlay_array);
        }
        (slot, value) => *slot = value,
    }
}

/// Drop duplicate cache entries by URL, keeping the highest priority seen.
///
/// Arrays concatenate across layers, so a cache present in several layers would
/// otherwise accumulate. Cache resolution sorts by priority, so the surviving
/// order is immaterial; this only bounds growth.
fn dedupe_caches(caches: &mut Vec<CacheEntry>) {
    let mut result: Vec<CacheEntry> = Vec::new();
    for entry in caches.drain(..) {
        if let Some(existing) = result.iter_mut().find(|e| e.url == entry.url) {
            existing.priority = existing.priority.max(entry.priority);
        } else {
            result.push(entry);
        }
    }
    *caches = result;
}

/// Drop duplicate strings in place, keeping the first occurrence.
fn dedupe_strings(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

/// Whether the registry config file at `path` exists and contributes a `url`.
///
/// A `url`-bearing file *defines* a registry (a seed or a self-sufficient
/// writable-layer definition); a file without one is a pure overlay that only
/// adjusts an inherited definition. Returns `false` for a missing, unreadable,
/// or malformed file. Used to decide registry removal
/// ([`ApmConfig::registry_config_path_for_update`] is the mutation counterpart)
/// and orphaned-overlay pruning (see [`crate::clean`]).
pub(crate) fn registry_file_has_url(path: &Path) -> bool {
    let Ok(content) = std::fs::read_to_string(path) else {
        return false;
    };
    toml::from_str::<toml::Value>(&content)
        .ok()
        .and_then(|value| {
            value
                .get("registry")
                .and_then(toml::Value::as_table)
                .map(|table| table.contains_key("url"))
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn write_file(dir: &Path, name: &str, content: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    /// Ordered layer list from `TempDir`s, lowest precedence first.
    fn layers(dirs: &[&TempDir]) -> Vec<PathBuf> {
        dirs.iter().map(|d| d.path().to_path_buf()).collect()
    }

    /// Find the loaded registry named `name`, panicking when absent.
    fn find<'a>(
        regs: &'a [(RegistryConfig, Option<RegistryState>)],
        name: &str,
    ) -> &'a (RegistryConfig, Option<RegistryState>) {
        regs.iter()
            .find(|(cfg, _)| cfg.name == name)
            .expect("expected registry present")
    }

    #[test]
    fn load_settings_from_single_layer() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "apm.conf",
            r#"
[settings]
assume_yes = true
parallel_downloads = 16
"#,
        );
        let settings = ApmConfig::load_settings(&layers(&[&tmp])).unwrap();
        assert!(settings.assume_yes);
        assert_eq!(settings.parallel_downloads, 16);
    }

    #[test]
    fn load_settings_deep_merges_layers_per_field() {
        let seed = TempDir::new().unwrap();
        let writable = TempDir::new().unwrap();
        // Seed sets two fields; the higher layer overrides one and leaves the
        // other to inherit.
        write_file(
            seed.path(),
            "apm.conf",
            r#"
[settings]
assume_yes = true
parallel_downloads = 2
"#,
        );
        write_file(
            writable.path(),
            "apm.conf",
            r#"
[settings]
parallel_downloads = 8
"#,
        );
        // layers = [seed, writable], writable wins per field.
        let settings = ApmConfig::load_settings(&layers(&[&seed, &writable])).unwrap();
        assert_eq!(settings.parallel_downloads, 8); // overridden
        assert!(settings.assume_yes); // inherited from the seed
    }

    #[test]
    fn load_settings_defaults_when_missing() {
        let tmp = TempDir::new().unwrap();
        let settings = ApmConfig::load_settings(&layers(&[&tmp])).unwrap();
        assert!(!settings.assume_yes);
        assert_eq!(settings.parallel_downloads, 4);
    }

    #[test]
    fn load_settings_rejects_zero_parallel_downloads() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "apm.conf",
            r#"
[settings]
parallel_downloads = 0
"#,
        );

        let err = ApmConfig::load_settings(&layers(&[&tmp])).unwrap_err();
        assert!(
            err.to_string()
                .contains("parallel_downloads must be at least 1")
        );
    }

    #[test]
    fn load_settings_rejects_relative_credential_pcr_public_key() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "apm.conf",
            r#"
[settings]
credential_pcr_public_key = "keys/pcr.pem"
"#,
        );

        let err = ApmConfig::load_settings(&layers(&[&tmp])).unwrap_err();
        assert!(err.to_string().contains("credential_pcr_public_key"));
    }

    #[test]
    fn load_registries_from_dir() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
priority = 500
"#,
        );
        write_file(
            tmp.path(),
            "registries.d/aos-extra.toml",
            r#"
[registry]
name = "aos-extra"
url = "https://registry.aos.dev/extra"
priority = 400
"#,
        );

        let registries = ApmConfig::load_registries(&layers(&[&tmp])).unwrap();
        assert_eq!(registries.len(), 2);
        // Sorted by priority descending
        assert_eq!(registries[0].0.name, "aos-core");
        assert_eq!(registries[1].0.name, "aos-extra");
    }

    #[test]
    fn load_registries_keys_by_file_stem_not_name_field() {
        let tmp = TempDir::new().unwrap();
        // No `name` field: identity comes from the file stem.
        write_file(
            tmp.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
url = "https://registry.aos.dev/core"
"#,
        );
        let registries = ApmConfig::load_registries(&layers(&[&tmp])).unwrap();
        assert_eq!(registries.len(), 1);
        assert_eq!(registries[0].0.name, "aos-core");
    }

    #[test]
    fn load_registries_rejects_name_stem_mismatch() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
name = "other"
url = "https://registry.aos.dev/core"
"#,
        );
        let err = ApmConfig::load_registries(&layers(&[&tmp])).unwrap_err();
        assert!(err.to_string().contains("must match the file stem"));
    }

    #[test]
    fn load_registries_rejects_invalid_stem() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "registries.d/bad name.toml",
            r#"
[registry]
url = "https://registry.aos.dev/core"
"#,
        );
        let err = ApmConfig::load_registries(&layers(&[&tmp])).unwrap_err();
        assert!(err.to_string().contains("validating registry name"));
    }

    #[test]
    fn writable_layer_overrides_seed_per_field() {
        let seed = TempDir::new().unwrap();
        let writable = TempDir::new().unwrap();

        write_file(
            seed.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
priority = 500
"#,
        );
        // Higher layer overrides only priority; url is inherited from the seed.
        write_file(
            writable.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
priority = 600
"#,
        );

        let registries = ApmConfig::load_registries(&layers(&[&seed, &writable])).unwrap();
        assert_eq!(registries.len(), 1);
        let (cfg, _) = find(&registries, "aos-core");
        assert_eq!(cfg.url, "https://registry.aos.dev/core"); // inherited seed url
        assert_eq!(cfg.priority, 600); // overridden by writable layer
    }

    #[test]
    fn state_overlay_merges_onto_seed_definition() {
        let seed = TempDir::new().unwrap();
        let writable = TempDir::new().unwrap();

        write_file(
            seed.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[registry.signing]
required = true
public_key = "aos-core:Ed25519:abc123"
"#,
        );
        // A minimal /var delta: just sync state, no identity boilerplate.
        write_file(
            writable.path(),
            "registries.d/aos-core.toml",
            r#"
[registry.state]
last_commit = "deadbeef"
floor = "1.2.0"
bucket = 10
"#,
        );

        let registries = ApmConfig::load_registries(&layers(&[&seed, &writable])).unwrap();
        let (cfg, state) = find(&registries, "aos-core");
        // Seed-defined fields survive.
        assert_eq!(cfg.url, "https://registry.aos.dev/core");
        assert!(cfg.signing.is_some());
        // Overlay state is picked up.
        let state = state.as_ref().expect("state present");
        assert_eq!(state.last_commit.as_deref(), Some("deadbeef"));
        assert_eq!(state.floor.as_deref(), Some("1.2.0"));
        assert_eq!(state.bucket, Some(10));
    }

    #[test]
    fn seed_url_bump_takes_effect_over_existing_overlay() {
        // The central property: a later image bump that changes the seeded url
        // still takes effect, because the /var overlay only carries the fields
        // the runtime touched (here, state) — never a shadowing url copy.
        let seed = TempDir::new().unwrap();
        let writable = TempDir::new().unwrap();
        write_file(
            seed.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
name = "aos-core"
url = "https://cdn-v2.aos.dev/core"
"#,
        );
        write_file(
            writable.path(),
            "registries.d/aos-core.toml",
            r#"
[registry.state]
last_commit = "deadbeef"
"#,
        );
        let registries = ApmConfig::load_registries(&layers(&[&seed, &writable])).unwrap();
        let (cfg, _) = find(&registries, "aos-core");
        assert_eq!(cfg.url, "https://cdn-v2.aos.dev/core");
    }

    #[test]
    fn enabled_overlay_flips_seeded_registry() {
        let seed = TempDir::new().unwrap();
        let writable = TempDir::new().unwrap();
        write_file(
            seed.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
enabled = true
"#,
        );
        write_file(
            writable.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
enabled = false
"#,
        );
        let registries = ApmConfig::load_registries(&layers(&[&seed, &writable])).unwrap();
        let (cfg, _) = find(&registries, "aos-core");
        assert!(!cfg.enabled);
    }

    #[test]
    fn caches_concatenate_then_dedupe_by_url() {
        let seed = TempDir::new().unwrap();
        let writable = TempDir::new().unwrap();
        write_file(
            seed.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"

[[registry.caches]]
url = "https://cache-a.aos.dev"
priority = 100
"#,
        );
        write_file(
            writable.path(),
            "registries.d/aos-core.toml",
            r#"
[[registry.caches]]
url = "https://cache-b.aos.dev"
priority = 200

[[registry.caches]]
url = "https://cache-a.aos.dev"
priority = 300
"#,
        );
        let registries = ApmConfig::load_registries(&layers(&[&seed, &writable])).unwrap();
        let (cfg, _) = find(&registries, "aos-core");
        // cache-a is deduped to a single entry keeping the highest priority.
        assert_eq!(cfg.caches.len(), 2);
        let cache_a = cfg
            .caches
            .iter()
            .find(|c| c.url == "https://cache-a.aos.dev")
            .unwrap();
        assert_eq!(cache_a.priority, 300);
    }

    #[test]
    fn blank_seed_file_is_ignored() {
        let seed = TempDir::new().unwrap();
        // An emptied seed (the operator blanked it through host.nix) contributes
        // nothing and is never an error.
        write_file(seed.path(), "registries.d/aos-core.toml", "\n");
        let registries = ApmConfig::load_registries(&layers(&[&seed])).unwrap();
        assert!(registries.is_empty());
    }

    #[test]
    fn orphaned_overlay_without_url_is_dropped() {
        // A /var overlay whose seed has been blanked merges to a url-less
        // result and is dropped rather than resurrecting stale state.
        let writable = TempDir::new().unwrap();
        write_file(
            writable.path(),
            "registries.d/aos-core.toml",
            r#"
[registry.state]
last_commit = "deadbeef"
floor = "9.9.9"
"#,
        );
        let registries = ApmConfig::load_registries(&layers(&[&writable])).unwrap();
        assert!(registries.is_empty());
    }

    #[test]
    fn malformed_layer_file_is_skipped() {
        let seed = TempDir::new().unwrap();
        write_file(
            seed.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
"#,
        );
        // A second registry file is malformed; it must not fail the whole load.
        write_file(
            seed.path(),
            "registries.d/broken.toml",
            "this is = = not toml",
        );
        let registries = ApmConfig::load_registries(&layers(&[&seed])).unwrap();
        assert_eq!(registries.len(), 1);
        assert_eq!(registries[0].0.name, "aos-core");
    }

    #[test]
    fn registry_with_channel_loads() {
        let tmp = TempDir::new().unwrap();
        write_file(
            tmp.path(),
            "registries.d/aos-core.toml",
            r#"
[registry]
name = "aos-core"
url = "https://registry.aos.dev/core"
channel = "stable"
max_staleness_seconds = 604800
"#,
        );
        let registries = ApmConfig::load_registries(&layers(&[&tmp])).unwrap();
        let (config, state) = find(&registries, "aos-core");
        assert_eq!(config.channel.as_deref(), Some("stable"));
        assert_eq!(config.max_staleness_seconds, Some(604800));
        assert!(state.is_none());
    }

    #[test]
    fn deep_merge_combines_tables_arrays_and_scalars() {
        let mut base: toml::Value = toml::from_str(
            r#"
scalar = 1
[table]
keep = "base"
override = "base"
[[array]]
v = 1
"#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
scalar = 2
[table]
override = "overlay"
added = "overlay"
[[array]]
v = 2
"#,
        )
        .unwrap();
        deep_merge(&mut base, overlay);
        assert_eq!(base["scalar"].as_integer(), Some(2)); // scalar overridden
        assert_eq!(base["table"]["keep"].as_str(), Some("base")); // inherited
        assert_eq!(base["table"]["override"].as_str(), Some("overlay"));
        assert_eq!(base["table"]["added"].as_str(), Some("overlay"));
        // arrays concatenate, base entries first
        let array = base["array"].as_array().unwrap();
        assert_eq!(array.len(), 2);
        assert_eq!(array[0]["v"].as_integer(), Some(1));
        assert_eq!(array[1]["v"].as_integer(), Some(2));
    }

    #[test]
    fn enabled_registries_filter() {
        let config = ApmConfig {
            settings: ApmSettings::default(),
            registries: vec![
                (
                    RegistryConfig {
                        name: "enabled".into(),
                        url: "https://a.dev".into(),
                        priority: 500,
                        enabled: true,
                        commit: None,
                        branch: None,
                        channel: None,
                        tag: None,
                        version: None,
                        pin: None,
                        max_staleness_seconds: None,
                        caches: Vec::new(),
                        cache: Default::default(),
                        upload_auth: None,
                        signing_keys: Default::default(),
                        signing: None,
                    },
                    None,
                ),
                (
                    RegistryConfig {
                        name: "disabled".into(),
                        url: "https://b.dev".into(),
                        priority: 400,
                        enabled: false,
                        commit: None,
                        branch: None,
                        channel: None,
                        tag: None,
                        version: None,
                        pin: None,
                        max_staleness_seconds: None,
                        caches: Vec::new(),
                        cache: Default::default(),
                        upload_auth: None,
                        signing_keys: Default::default(),
                        signing: None,
                    },
                    None,
                ),
            ],
            scope: ProfileScope::User,
        };
        let enabled = config.enabled_registries();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].name, "enabled");
    }
}
